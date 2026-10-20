//go:build lab

package lab

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	clientv3 "go.etcd.io/etcd/client/v3"

	"github.com/rhwendt/port49/internal/store/etcd"
	"github.com/rhwendt/port49/internal/store/etcd/etcdtest"
	"github.com/rhwendt/port49/internal/tacacs/wire"
	"github.com/rhwendt/port49/internal/testpki"
)

const storeClaim = "When port49d's store hangs (etcd cut off from port49d), port49d answers a command FAIL " +
	"store_unavailable and a login ERROR store_unavailable within packet_deadline (2s), before the " +
	"device's own TACACS+ timeout, and the device acts as on L4's store outage, never as on a silent server; " +
	"once port49d closes its listeners on losing the store (its health checks, decision 37), the device acts as with " +
	"port49d stopped and break-glass logs in; and once the store returns and port49d listens again, an open " +
	"session's next command is answered from the context the store kept (plan 7d; spec §13 decisions 35 and 37)."

// storeLab is the lab's etcd: a TLS member with port49's roles, behind a
// proxy the test hangs, and the two stores: blocks that point the split's
// processes at it: block is port49d.yaml's (the daemon's identity, with the
// admin_socket etcd requires), brokerBlock port49-broker.yaml's (the
// broker's identity). keys counts what the keyspace holds, read as etcd's
// root.
func storeLab(t *testing.T) (block, brokerBlock string, proxy *etcdtest.Proxy, keys func() (int64, error)) {
	t.Helper()
	srv := etcdtest.Start(t, etcdtest.Options{TLS: true})
	var grants []etcdtest.Grant
	for _, g := range etcd.Roles("/port49/") {
		grants = append(grants, etcdtest.Grant{Role: g.Role, Key: g.Key, RangeEnd: g.RangeEnd, Write: g.Write})
	}
	srv.EnableAuth(t, grants, map[string][]string{"port49-daemon": {etcd.RoleDaemon}, "port49-broker": {etcd.RoleBroker}})
	proxy = etcdtest.NewProxy(t, strings.TrimPrefix(srv.Endpoint, "https://"))
	dc, dk := srv.ClientFiles(t, "port49-daemon")
	// port49d.yaml names the daemon's identity alone; the broker's is
	// port49-broker.yaml's (plan 7e, Ruling 1).
	block = fmt.Sprintf("\nstores:\n  directory:\n    backend: etcd\n    etcd:\n      endpoints: [https://%s]\n      ca_file: %s\n"+
		"      daemon: {cert_file: %s, key_file: %s}\n      hold_ttl: 60s\n",
		proxy.Addr(), filepath.Join(srv.Dir, "ca.pem"), dc, dk)
	bc, bk := srv.ClientFiles(t, "port49-broker")
	brokerBlock = fmt.Sprintf("\nstores:\n  directory:\n    backend: etcd\n    etcd:\n      endpoints: [https://%s]\n      ca_file: %s\n"+
		"      broker: {cert_file: %s, key_file: %s}\n      hold_ttl: 60s\n",
		proxy.Addr(), filepath.Join(srv.Dir, "ca.pem"), bc, bk)
	root := srv.Client(t, "root")
	keys = func() (int64, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		resp, err := root.Get(ctx, "/port49/", clientv3.WithPrefix(), clientv3.WithCountOnly())
		if err != nil {
			return 0, err
		}
		return resp.Count, nil
	}
	return block, brokerBlock, proxy, keys
}

// ctxIDOf is the ctx_id of the last authorize_command record for user
// since off, and its verdict and reason.
func ctxIDOf(recs []map[string]any, user string) (ctxID, verdict, reason string) {
	for _, r := range recs {
		if r["event"] != "authorize_command" {
			continue
		}
		if s, _ := r["session"].(map[string]any); s != nil && s["username"] == user {
			ctxID, _ = s["ctx_id"].(string)
			verdict, _ = r["verdict"].(string)
			reason, _ = r["reason"].(string)
		}
	}
	return ctxID, verdict, reason
}

// reasonsOf is every (event, verdict, reason) among recs, for asserting
// what a hung store answered.
func reasonsOf(recs []map[string]any, event string) []string {
	var out []string
	for _, r := range recs {
		if r["event"] == event {
			out = append(out, fmt.Sprintf("%v %v", r["verdict"], r["reason"]))
		}
	}
	return out
}

// replyTimes is, for every request the device sent from from to to, the
// time from its send to port49d's reply and the reply's status, as the
// capture saw them: the reply is the first packet at or after the
// request on the same connection's reverse stream (the device's port, as
// both directions show it) with the request's session_id and its seq_no
// plus one. A request with no reply is listed as unanswered.
func replyTimes(path, key string, from, to time.Time) []string {
	return replyTimesFrom(path, key, from, to, false)
}

// replyTimesFrom is replyTimes that, with server set, names the TACACS+
// server each reply came from (the split's two replicas).
func replyTimesFrom(path, key string, from, to time.Time, server bool) []string {
	pkts, _, err := pcapTACACSPackets(path, key)
	if err != nil {
		return []string{"capture unreadable: " + err.Error()}
	}
	var out []string
	for _, x := range exchangesIn(pkts, from, to) {
		p, reply := x.Req, x.Reply
		if reply == nil {
			out = append(out, fmt.Sprintf("%s seq %d unanswered", p.Kind(), p.Header.SeqNo))
			continue
		}
		via := ""
		if server {
			host, _, _ := strings.Cut(reply.Conn, ":")
			via = " from " + host
		}
		out = append(out, fmt.Sprintf("%s seq %d -> %s%s in %s", p.Kind(), p.Header.SeqNo, replyStatus(*reply), via,
			reply.At.Sub(p.At).Round(time.Millisecond)))
	}
	if len(out) == 0 {
		return []string{"no request in the capture"}
	}
	return out
}

// exchange is one request the device sent and the reply it got, nil when
// none came.
type exchange struct {
	Req   wirePacket
	Reply *wirePacket
}

// exchangesIn is every request the device sent between from and to, in
// capture order, each with the first reply on its connection and session at
// the next seq.
func exchangesIn(pkts []wirePacket, from, to time.Time) []exchange {
	var out []exchange
	for _, p := range pkts {
		if !p.FromDevice || p.At.Before(from) || p.At.After(to) {
			continue
		}
		var reply *wirePacket
		for i, q := range pkts {
			if !q.FromDevice && q.SrcPort == p.SrcPort && q.Header.SessionID == p.Header.SessionID &&
				q.Header.SeqNo == p.Header.SeqNo+1 && !q.At.Before(p.At) && (reply == nil || q.At.Before(reply.At)) {
				reply = &pkts[i]
			}
		}
		out = append(out, exchange{Req: p, Reply: reply})
	}
	return out
}

// cellGrade is what a step-3 cell that met port49d's dark measured.
type cellGrade int

const (
	cellInvalid cellGrade = iota // dark came first: measure it again
	cellValid                    // the hung store's answer was measured before dark
	cellFailed                   // port49d's answer broke the claim
)

func (g cellGrade) String() string {
	return [...]string{"invalid", "valid", "failed"}[g]
}

// hungLoginBeforeDark grades a step-3 token login during which port49d went
// dark at darkAt (decision 37), from the login's AUTHEN exchanges. The claim
// is port49d's answer: every verdict it gives a login while the store hangs,
// each AUTHEN reply that is not a GET prompt, is ERROR within deadline
// (packet_deadline). The first comes about 500ms into the hang and dark about
// 5s in, but a device whose failed login takes longer (Junos's and NX-OS's
// second try) meets dark before the login ends: its later tries find the
// listener closed and fall to the local method, where the token's user has no
// account, so the login is refused either way. Every exchange is graded: a
// verdict that is not ERROR, or comes late, fails the cell, and so does a
// request port49d still held past deadline when it went dark; darkAt is read
// by a poll and may be up to darkPoll late, which the hold is allowed. With
// none failed, the cell measured the hung store (valid) when at least one
// verdict was ERROR in time; a request dark cut off inside deadline is then
// the dark's, not port49d's. With no such verdict, dark came before port49d
// owed one, and the cell is unmeasured (invalid).
func hungLoginBeforeDark(xs []exchange, darkAt time.Time, deadline time.Duration) (cellGrade, string) {
	if darkAt.IsZero() {
		return cellInvalid, "no time was read for port49d's dark"
	}
	var answered []string
	unmeasured := "the device sent no AUTHEN verdict request before port49d went dark"
	for _, x := range xs {
		if x.Req.Header.Type != wire.TypeAuthen {
			continue
		}
		seq := x.Req.Header.SeqNo
		if x.Reply == nil {
			if held := darkAt.Sub(x.Req.At); held > deadline+darkPoll {
				return cellFailed, fmt.Sprintf("AUTHEN seq %d was unanswered %s, until port49d went dark, past packet_deadline %s",
					seq, held.Round(time.Millisecond), deadline)
			}
			unmeasured = fmt.Sprintf("AUTHEN seq %d was cut off by port49d's dark inside packet_deadline", seq)
			continue
		}
		st, in := replyStatus(*x.Reply), x.Reply.At.Sub(x.Req.At)
		switch {
		case strings.HasPrefix(st, "GET"):
			continue
		case !strings.HasPrefix(st, "ERROR"):
			return cellFailed, fmt.Sprintf("the hung store's login was answered %s (AUTHEN seq %d), not ERROR", st, seq)
		case in > deadline:
			return cellFailed, fmt.Sprintf("AUTHEN seq %d was answered ERROR in %s, past packet_deadline %s",
				seq, in.Round(time.Millisecond), deadline)
		}
		answered = append(answered, fmt.Sprintf("AUTHEN seq %d %s in %s", seq, st, in.Round(time.Millisecond)))
	}
	if len(answered) == 0 {
		return cellInvalid, unmeasured
	}
	return cellValid, "every verdict before dark was ERROR in time (" + strings.Join(answered, "; ") +
		"); the rest of the login met port49d's dark"
}

// replyStatus is a reply's status, by name.
func replyStatus(q wirePacket) string {
	_, st, ok := strings.Cut(q.decoded, "status=")
	if !ok {
		return "an undecoded reply"
	}
	st, _, _ = strings.Cut(st, " ")
	names := map[wire.Type]map[string]string{
		wire.TypeAuthor: {"0x1": "PASS_ADD", "0x2": "PASS_REPL", "0x10": "FAIL", "0x11": "ERROR", "0x21": "FOLLOW"},
		wire.TypeAcct:   {"0x1": "SUCCESS", "0x2": "ERROR", "0x21": "FOLLOW"},
	}[q.Header.Type]
	if name, ok := names[strings.Replace(st, "0x0", "0x", 1)]; ok {
		return name
	}
	return st
}

// storeOutcome is revokeOutcome that, when the command printed something
// without its version line, reads the shell again 3s later. vSRX redraws
// its prompt in the command's echo, so the prompt is matched before the
// output arrives; vJunos-router does not (L35's first vSRX run). The wait
// also lets late output drain before the next command, and on IOS-XE,
// whose refused command prints nothing (L4-error-cisco_iosxe.md (b)), it
// is 3s more of nothing.
func storeOutcome(platform string, sh *labShell, cmd string, fail func(string, ...any), what string) string {
	from := len(sh.c.transcript())
	out := revokeOutcome(platform, sh, cmd, fail, what)
	if !strings.HasPrefix(out, "printed something") {
		return out
	}
	time.Sleep(3 * time.Second)
	markers := []string{revokeVersion[platform]}
	if strings.HasPrefix(platform, "juniper_") {
		markers = append(markers, "Junos:", "Hostname:")
	}
	for _, line := range strings.Split(sh.c.transcript()[from:], "\n") {
		for _, m := range markers {
			if m != "" && strings.Contains(line, m) {
				return fmt.Sprintf("printed its output, read 3s after the prompt its echo carried: %s",
					l29Cell(strings.TrimSpace(line)))
			}
		}
	}
	return out + "; nothing more 3s later"
}

// listenAgain waits up to within for port49d to say, after off, that it
// listens, then for its TACACS+ port.
func (l *lab) listenAgain(off int64, within time.Duration) error {
	for deadline := time.Now().Add(within); time.Now().Before(deadline) &&
		len(l.errLinesSince(off, "listening on")) == 0; {
		time.Sleep(time.Second)
	}
	if len(l.errLinesSince(off, "listening on")) == 0 {
		return fmt.Errorf("port49d did not say it listens again within %s", within)
	}
	return l.awaitTACACS()
}

// labPacketDeadline is stores.directory.packet_deadline's default, which
// the lab's stores: block leaves unset: the bound on port49d's answer to a
// request while the store hangs.
const labPacketDeadline = 2 * time.Second

// storeAttempts is how many times one of step 3's cells is measured
// before it is recorded INVALID: the first, and three re-runs (Ruling
// T15-a).
const storeAttempts = 4

func TestStoreOutageEndToEnd(t *testing.T) {
	eachPlatform(t, func(t *testing.T, l *lab) {
		var failed []string
		fail := func(format string, args ...any) { failed = append(failed, fmt.Sprintf(format, args...)) }
		sessionOnly := strings.HasPrefix(l.p.name, "juniper_")
		var obs strings.Builder
		row := func(step, what string) { fmt.Fprintf(&obs, "| %s | %s |\n", step, l29Cell(what)) }
		wide := func(step, what string) { fmt.Fprintf(&obs, "| %s | %s |\n", step, wideCell(what)) }
		obs.WriteString("| step | observed |\n|---|---|\n")
		// lit says, at the end of a cell, whether port49d closed its
		// listeners at any point since off (IB1: also after the store came
		// back).
		lit := func(off int64, what string) bool {
			if dark := l.errLinesSince(off, "closing every listener"); len(dark) > 0 {
				row(what+", validity", "port49d closed its listeners during this cell: "+dark[0])
				return false
			}
			return true
		}

		// port49-broker and port49d A on one store (plan 7e): the broker mints,
		// A serves TACACS+. The second server is not pushed to the device, so
		// it lists the one server L35 was measured with, and the cells below
		// measure what they measured before the broker left port49d. The
		// member is this run's own, so the keyspace starts empty: no record of
		// an earlier form is there to read (Task 13b's C2).
		//
		// PORT49_LAB_L35_ENTRY names the run a re-check of L35 after L37 (the
		// same go test process, so the device carries whatever L37's teardown
		// left): its capture and note are the entry's, never L35's closed
		// ones, and its result is appended to L37's note (Task 17 review I-6).
		entry := "L35"
		if e := os.Getenv("PORT49_LAB_L35_ENTRY"); e != "" {
			entry = e
			rb := l.serverReadback(t)
			row("0. the device's TACACS+ servers, read back before this run", rb)
			if err := serverListed(l.p.name, rb, false); err != nil {
				fail("a second server was left on the device: %v", err)
			}
		}
		s := l.startSplit(t, splitCfg{})
		proxy := s.Proxy
		row("0. the keyspace before the first process starts", fmt.Sprintf("%d keys under /port49/", s.KeysAtStart))
		start := func(what string) {
			t.Helper()
			if err := s.StartA(); err != nil {
				t.Fatalf("port49d would not start on etcd (%s): %v", what, err)
			}
		}
		stop := l.capture(t, entry)
		defer stop()
		capPath := filepath.Join(root, "tests", "lab", "captures", entry+"-"+l.p.name+".pcap")

		// 1. Baseline.
		off := l.mark()
		sock, _, stopAgent := revokeAgent(t)
		defer stopAgent()
		_, tok1 := l29Mint(sock, l.p.node)
		_, spare := l29Mint(sock, l.p.node)
		if tok1 == "" || spare == "" {
			t.Fatal("the agent minted no token on etcd")
		}
		sh, err := l.shell(sliceUser, tok1)
		if err != nil {
			t.Fatalf("SSH login on etcd: %v\nrecords:%s", err, summarize(l.recordsSince(off)))
		}
		defer sh.Close()
		before := storeOutcome(l.p.name, sh, "show version", fail, "baseline")
		row("1. baseline, `show version`", before)
		ctxBefore, _, _ := ctxIDOf(l.waitForRecords(off, 30*time.Second, func(rs []map[string]any) bool {
			id, _, _ := ctxIDOf(rs, sliceUser)
			return id != "" || sessionOnly
		}), sliceUser)

		// 2. A restart on the same store.
		errOff := l.errLogSize()
		if err := l.stopDaemon(); err != nil {
			t.Fatal(err)
		}
		start("restart")
		wide("2. port49d's start lines", strings.Join(append(l.errLinesSince(errOff, "purged"),
			l.errLinesSince(errOff, "carried onto the policy in force")...), " / "))
		off = l.mark()
		after := storeOutcome(l.p.name, sh, "show version", fail, "after the restart")
		ctxAfter, verdict, reason := ctxIDOf(l.waitForRecords(off, 30*time.Second, func(rs []map[string]any) bool {
			id, _, _ := ctxIDOf(rs, sliceUser)
			return id != "" || sessionOnly
		}), sliceUser)
		row("2. after the restart, the open session's `show version`",
			fmt.Sprintf("%s; record %s %s, ctx_id %s (before: %s)", after, verdict, reason, ctxAfter, ctxBefore))
		if !strings.HasPrefix(after, "printed its output") {
			fail("the open session's next command did not run after the restart: %s", after)
		}
		if !sessionOnly && (ctxAfter != ctxBefore || verdict != "permit") {
			fail("the next command was not answered from the kept context: %s %s %s/%s", verdict, reason, ctxAfter, ctxBefore)
		}
		// On the split the purge of unspent tokens is port49-broker's, at its
		// own start and on a changed bundle (plan 7e): a port49d restart purges
		// nothing, so a token minted before it still logs in.
		if _, err := l.loginWithin(sliceUser, spare, 60*time.Second, "show version"); err != nil {
			fail("a token minted before the port49d restart did not log in: %v", err)
		}
		recs := l.waitForRecords(off, 30*time.Second, func(rs []map[string]any) bool { return redeemReason(rs, sha(spare)) != "" })
		row("2. a token minted before the port49d restart", "redeemed: "+redeemReason(recs, sha(spare)))
		if redeemReason(recs, sha(spare)) != "token_redeemed" {
			fail("the pre-restart token was answered %q, not token_redeemed", redeemReason(recs, sha(spare)))
		}
		if !lit(errOff, "2.") {
			fail("port49d closed its listeners during step 2")
		}

		// 3. The store hangs. Every time below that a device sees is the
		// capture's, request to reply (pre-flight I17). Each measurement
		// gets its own hang, the store back between them: port49d's health
		// checks close its listeners after close_after (5) failed checks a
		// second apart (decision 37, step 4's bound), and a login or a
		// break-glass login can take most of that on its own. A cell during which port49d
		// closed its listeners, while the store hung or after it came back
		// (IB1), measured port49d dark, not a hung store: it is marked
		// INVALID and measured again on a fresh hang, up to storeAttempts
		// times (Ruling T15-a). The token login is the exception: a failed
		// login on vJunos, vSRX and NX-OS outlasts the 5s to dark, so a cell
		// that met dark is graded by hungLoginBeforeDark on port49d's verdict
		// before it.
		off = l.mark()
		type window struct {
			what     string
			from, to time.Time
		}
		var windows []window
		var berr error
		// measure is called twice per attempt: with a nil fail before the
		// hang, to prepare, and then to measure. metDark, when not nil,
		// grades a cell that met port49d's dark from the capture of the hang
		// and when dark came.
		hang := func(what string, measure func(attempt int, fail func(string, ...any)),
			metDark func(from, to, darkAt time.Time) (cellGrade, string)) {
			for attempt := 1; attempt <= storeAttempts; attempt++ {
				var cellFails []string
				cellFail := func(format string, args ...any) { cellFails = append(cellFails, fmt.Sprintf(format, args...)) }
				measure(attempt, nil) // what the cell spends, a token, is minted while the store answers
				errOff = l.errLogSize()
				stopWatch := make(chan struct{})
				darkAt := darkWatch(stopWatch, func() bool { return len(l.errLinesSince(errOff, darkCloseText)) > 0 })
				from := time.Now()
				proxy.Hang(true)
				measure(attempt, cellFail)
				proxy.Hang(false)
				to := time.Now()
				// The circuits' probes, and the fence's next answered read.
				time.Sleep(15 * time.Second)
				close(stopWatch)
				label := fmt.Sprintf("3. %s, attempt %d (hung %s)", what, attempt, to.Sub(from).Round(time.Second))
				if lit(errOff, label) {
					<-darkAt
					windows = append(windows, window{label, from, to})
					failed = append(failed, cellFails...)
					return
				}
				grade, why := cellInvalid, "port49d closed its listeners before the cell ended"
				if at := <-darkAt; metDark != nil {
					l.flushCapture(t)
					grade, why = metDark(from, to, at)
				}
				switch grade {
				case cellValid:
					row(label, "valid, port49d went dark during it: "+why)
					windows = append(windows, window{label, from, to})
					failed = append(failed, cellFails...)
				case cellFailed:
					row(label, "FAILED, port49d went dark during it: "+why)
					fail("step 3 (%s): %s", what, why)
					failed = append(failed, cellFails...)
				default:
					row(label, "INVALID: "+why+"; measured again")
				}
				if err := l.listenAgain(errOff, 150*time.Second); err != nil {
					t.Fatalf("after a cell that met port49d's dark (%s): %v", label, err)
				}
				if grade != cellInvalid {
					return
				}
			}
			fail("step 3 (%s) was INVALID on all %d attempts: port49d closed its listeners first every time", what, storeAttempts)
		}
		if !sessionOnly {
			hang("the open session's command", func(attempt int, f func(string, ...any)) {
				if f == nil {
					return
				}
				hung := storeOutcome(l.p.name, sh, "show version", f, "with the store hung")
				switch {
				case strings.HasPrefix(hung, "refused"):
				case strings.HasPrefix(hung, "printed something"):
					// IOS-XE prints nothing for a refused command, not even
					// the FAIL's server_msg (tests/lab/results/L4-error-cisco_iosxe.md
					// (b)): no output line is the refusal. The FAIL itself is
					// read off the wire, and its record, below.
					hung = "refused silently, no output: " + hung
				default:
					f("with the store hung the next command was not refused: %s", hung)
				}
				row(fmt.Sprintf("3. store hung, the open session's `show version` (attempt %d)", attempt), hung)
			}, nil)
		}
		var tok3 string
		hang("the token login", func(attempt int, f func(string, ...any)) {
			if f == nil {
				_, tok3 = l29Mint(sock, l.p.node)
				if tok3 == "" {
					t.Fatal("the agent minted no token for step 3's login")
				}
				return
			}
			_, lerr := l.loginWithin(sliceUser, tok3, 60*time.Second, "show version")
			row(fmt.Sprintf("3. store hung, a token login (attempt %d)", attempt), fmt.Sprint(lerr))
			if lerr == nil {
				f("a token login succeeded with the store hung")
			}
		}, func(from, to, darkAt time.Time) (cellGrade, string) {
			pkts, _, err := pcapTACACSPackets(capPath, labKeyDefault)
			if err != nil {
				return cellInvalid, "the capture is unreadable: " + err.Error()
			}
			return hungLoginBeforeDark(exchangesIn(pkts, from, to), darkAt, labPacketDeadline)
		})
		hang("break-glass", func(attempt int, f func(string, ...any)) {
			if f == nil {
				return
			}
			var outs []string
			outs, berr = l.loginWithin(breakglassUser, breakglassPassword, 60*time.Second, "show version")
			row(fmt.Sprintf("3. store hung, break-glass and `show version` (attempt %d)", attempt),
				fmt.Sprintf("login err %v; printed %s (compare tests/lab/results/L4-error-%s.md)", berr,
					firstOut(outs), l.p.name))
		}, nil)
		recs = l.waitForRecords(off, 20*time.Second, func([]map[string]any) bool { return true })
		cmds, redeems := reasonsOf(recs, "authorize_command"), reasonsOf(recs, "redeem")
		wide("3. records", fmt.Sprintf("authorize_command %v; redeem %v; authorize_session %v; accounting %v", cmds, redeems,
			reasonsOf(recs, "authorize_session"), reasonsOf(recs, "accounting")))
		if !sessionOnly && !contains(cmds, "deny store_unavailable") {
			fail("no command was answered deny store_unavailable with the store hung: %v", cmds)
		}
		// A redeem answered ERROR is recorded verdict deny: a record's
		// verdict is permit or deny (authen.storeError); the ERROR is the
		// wire's, read from the capture below.
		if !contains(redeems, "deny store_unavailable") {
			fail("no login was answered store_unavailable with the store hung: %v", redeems)
		}
		l.flushCapture(t)
		for _, w := range windows {
			times := strings.Join(replyTimes(capPath, labKeyDefault, w.from, w.to), "; ")
			wide(w.what+", request-to-reply from the capture", times)
			if strings.Contains(w.what, "token login") && !strings.Contains(times, "AUTHEN seq 1 -> ERROR") &&
				!strings.Contains(times, "AUTHEN seq 3 -> ERROR") {
				fail("the hung store's token login was not answered ERROR on the wire: %s", times)
			}
			if strings.Contains(w.what, "open session") && !strings.Contains(times, "AUTHOR seq 1 -> FAIL") {
				fail("the hung store's command was not answered FAIL on the wire: %s", times)
			}
		}

		// 4. port49d closes its listeners on losing the store, and stays up.
		errOff = l.errLogSize()
		proxy.Hang(true)
		hungAt := time.Now()
		// port49d goes dark on decision 37's health checks: close_after (5)
		// consecutive failed checks, interval (1s) apart, about 5s in. The
		// line says "consecutive store health checks failed" and no circuit
		// opens first: the check runs below the guard. The wait runs to 180s
		// so the observed time is always written; the bound is the
		// configuration's (healthDarkBound), and a time past it fails.
		dts := waitDark(hungAt, 180*time.Second, func(sub string) bool { return len(l.errLinesSince(errOff, sub)) > 0 })
		dark := l.errLinesSince(errOff, "closing every listener")
		wide("4. port49d's line", fmt.Sprintf("%s after the hang: %s | %s", dts[0].Dark.Round(100*time.Millisecond),
			strings.Join(dark, " / "), dts[0].describe()))
		failed = append(failed, dts[0].verdict("port49d")...)
		time.Sleep(5 * time.Second) // the drain
		if len(l.errLinesSince(errOff, "waiting for the store again")) == 0 {
			fail("port49d did not say it waits for the store")
		}
		quarantine := "compare tests/lab/results/quarantine-" + l.p.name + ".md"
		if _, err := os.Stat(filepath.Join(root, "tests", "lab", "results", "quarantine-"+l.p.name+".md")); err != nil {
			quarantine = "no quarantine note for this image"
		}
		stopped := storeOutcome(l.p.name, sh, "show version", func(string, ...any) {}, "with the listeners closed")
		row("4. listeners closed, the open session's `show version`", stopped+" ("+quarantine+")")
		bgAt := time.Now()
		outs, berr := l.loginWithin(breakglassUser, breakglassPassword, 60*time.Second, "show version")
		row("4. listeners closed, break-glass and `show version`", fmt.Sprintf("login err %v in %s; printed %s", berr,
			time.Since(bgAt).Round(100*time.Millisecond), firstOut(outs)))
		if berr != nil {
			fail("break-glass did not log in with port49d's listeners closed: %v", berr)
		}

		// 5. The store returns; the same port49d listens again, unprompted.
		errOff = l.errLogSize()
		proxy.Hang(false)
		backAt := time.Now()
		if err := l.listenAgain(errOff, 150*time.Second); err != nil {
			t.Fatalf("port49d did not listen again after the store returned: %v", err)
		}
		wide("5. port49d's start lines", fmt.Sprintf("listening %s after the store returned: %s",
			time.Since(backAt).Round(time.Second), strings.Join(append(l.errLinesSince(errOff, "purged"),
				l.errLinesSince(errOff, "carried onto the policy in force")...), " / ")))
		off = l.mark()
		back := storeOutcome(l.p.name, sh, "show version", fail, "after the store returned")
		ctxBack, verdict, reason := ctxIDOf(l.waitForRecords(off, 30*time.Second, func(rs []map[string]any) bool {
			id, _, _ := ctxIDOf(rs, sliceUser)
			return id != "" || sessionOnly
		}), sliceUser)
		row("5. store back, the open session's `show version`",
			fmt.Sprintf("%s; record %s %s, ctx_id %s", back, verdict, reason, ctxBack))
		if !sessionOnly && (ctxBack != ctxBefore || verdict != "permit") {
			fail("after the store returned the next command was not answered from the kept context: %s %s %s",
				verdict, reason, ctxBack)
		}
		if sessionOnly && !strings.HasPrefix(back, "printed its output") {
			fail("after the store returned the open session's next command did not run: %s", back)
		}
		if lines := l.errLinesSince(errOff, "closing every listener"); len(lines) > 0 {
			row("5. validity", "port49d closed its listeners again after the store returned: "+lines[0])
			fail("port49d closed its listeners again after the store returned")
		}

		note := obs.String()
		if len(failed) > 0 {
			note += "\n**Failed:**\n\n- " + strings.Join(failed, "\n- ") + "\n"
		}
		if entry == "L35" {
			l.result(t, "L35", storeClaim, note)
		} else {
			l.appendNote(t, "L37", "## "+entry+": step 3's cells and break-glass, on the device L37 left\n\n"+
				"Compared with L35-"+l.p.name+".md, only step 3's cells are the same by design (reply times, the "+
				"device's output text, break-glass); step 2's token (`token_redeemed`, not `token_not_found`), "+
				"step 4's dark time and step 5's listening-again time differ on the split, and the daemon's "+
				"start-line rows are the broker's. Row 0's readback shows no second server.\n\n"+note)
		}
		if len(failed) > 0 {
			t.Fatalf("L35 on %s: %s", l.p.name, strings.Join(failed, "; "))
		}
	})
}

// firstOut is the first non-empty line a login's first command printed.
func firstOut(outs []string) string {
	if len(outs) == 0 {
		return "nothing"
	}
	if line := firstLine(outs[0]); line != "" {
		return "'" + line + "'"
	}
	return "nothing"
}

// wideCell is l29Cell for a cell that quotes several lines or records:
// one line, bounded at 2000 bytes.
func wideCell(s string) string {
	s = oneLine(strings.ReplaceAll(s, "`", "'"))
	if s == "" {
		return "nothing"
	}
	if len(s) > 2000 {
		s = s[:2000] + "…"
	}
	return "`" + s + "`"
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// A snapshot restored under a running port49d (Task 15's carries)
// ---------------------------------------------------------------------------

const restoreClaim = "A real `etcdutl snapshot restore --bump-revision 1000000000 --mark-compacted` under a running " +
	"port49d leaves no revision reused; a context written again since the snapshot is denied store_unavailable " +
	"(the ledger) and revoked by the next refresh pass, and a new login works; " +
	"`port49d store-roles`' etcdctl lines, run by a real etcdctl, provision the roles port49d starts under " +
	"(design §12, Backups; spec §13 decision 35; Ruling T13b-a)."

// realEtcd is one etcd member run from the release binaries in dir
// (PORT49_LAB_ETCD_BIN), with TLS and client-certificate authentication
// under a CA of the test's own, so that a restore is etcd's own, not the
// embedded member's.
type realEtcd struct {
	bin, pki      string
	name          string
	client, peer  string // host:port
	cmd           *exec.Cmd
	done          chan struct{}
	logPath       string
	rootC, rootK  string
	ca            string
	daemC, daemK  string
	brokC, brokK  string
	data, restore string
}

func freeAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().String()
}

func newRealEtcd(t *testing.T, bin string) *realEtcd {
	t.Helper()
	e := &realEtcd{bin: bin, pki: t.TempDir(), name: "lab", client: freeAddr(t), peer: freeAddr(t)}
	e.data, e.restore = filepath.Join(t.TempDir(), "data"), filepath.Join(t.TempDir(), "restored")
	e.logPath = filepath.Join(root, "tests", "lab", "logs", "etcd-restore.log")
	now := time.Now()
	ca, err := testpki.NewCA("L35 restore etcd CA", now.Add(-time.Hour), now.Add(24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	write := func(name string, body []byte) string {
		p := filepath.Join(e.pki, name)
		if err := os.WriteFile(p, body, 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	e.ca = write("ca.pem", ca.PEM())
	issue := func(leaf testpki.Leaf, name string) (string, string) {
		leaf.NotBefore, leaf.NotAfter = now.Add(-time.Hour), now.Add(24*time.Hour)
		c, err := ca.Issue(leaf)
		if err != nil {
			t.Fatal(err)
		}
		cp, kp, err := testpki.PEMs(c)
		if err != nil {
			t.Fatal(err)
		}
		return write(name+".pem", cp), write(name+"-key.pem", kp)
	}
	issue(testpki.Leaf{CommonName: "etcd", IPs: testpki.Loopback(), NoExtKeyUsage: true}, "server")
	e.rootC, e.rootK = issue(testpki.Leaf{CommonName: "root", Client: true}, "root")
	e.daemC, e.daemK = issue(testpki.Leaf{CommonName: "port49-daemon", Client: true}, "port49-daemon")
	e.brokC, e.brokK = issue(testpki.Leaf{CommonName: "port49-broker", Client: true}, "port49-broker")
	t.Cleanup(e.stop)
	return e
}

// start runs the member on dir, and waits until it answers.
func (e *realEtcd) start(t *testing.T, dir string) {
	t.Helper()
	lf, err := os.OpenFile(e.logPath, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	e.cmd = exec.Command(filepath.Join(e.bin, "etcd"), "--name", e.name, "--data-dir", dir,
		"--listen-client-urls", "https://"+e.client, "--advertise-client-urls", "https://"+e.client,
		"--listen-peer-urls", "http://"+e.peer, "--initial-advertise-peer-urls", "http://"+e.peer,
		"--initial-cluster", e.name+"=http://"+e.peer,
		"--cert-file", filepath.Join(e.pki, "server.pem"), "--key-file", filepath.Join(e.pki, "server-key.pem"),
		"--trusted-ca-file", e.ca, "--client-cert-auth")
	e.cmd.Stdout, e.cmd.Stderr = lf, lf
	if err := e.cmd.Start(); err != nil {
		lf.Close()
		t.Fatal(err)
	}
	e.done = make(chan struct{})
	go func() { e.cmd.Wait(); lf.Close(); close(e.done) }()
	for deadline := time.Now().Add(30 * time.Second); time.Now().Before(deadline); time.Sleep(250 * time.Millisecond) {
		if _, err := e.revision(); err == nil {
			return
		}
	}
	t.Fatalf("etcd did not answer within 30s; see %s", e.logPath)
}

// stop ends the member, SIGTERM first.
func (e *realEtcd) stop() {
	if e.cmd == nil || e.cmd.Process == nil {
		return
	}
	e.cmd.Process.Signal(syscall.SIGTERM)
	select {
	case <-e.done:
	case <-time.After(15 * time.Second):
		e.cmd.Process.Kill()
		<-e.done
	}
	e.cmd = nil
}

// ctl runs etcdctl as etcd's root with args, and returns its combined
// output. Nothing it prints here is a credential: the key files are
// passed by path.
func (e *realEtcd) ctl(args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, filepath.Join(e.bin, "etcdctl"),
		append([]string{"--endpoints", "https://" + e.client, "--cacert", e.ca, "--cert", e.rootC, "--key", e.rootK,
			"--dial-timeout", "3s", "--command-timeout", "5s"}, args...)...).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

// revision is the store's current revision, from a read's header.
func (e *realEtcd) revision() (int64, error) {
	out, err := e.ctl("get", "/port49-restore-probe", "-w", "json")
	if err != nil {
		return 0, fmt.Errorf("%v: %s", err, out)
	}
	var r struct {
		Header struct {
			Revision int64 `json:"revision"`
		} `json:"header"`
	}
	if err := json.Unmarshal([]byte(out), &r); err != nil {
		return 0, err
	}
	return r.Header.Revision, nil
}

// keys counts the keys under prefix.
func (e *realEtcd) keys(prefix string) (int64, error) {
	out, err := e.ctl("get", prefix, "--prefix", "--keys-only", "-w", "json")
	if err != nil {
		return 0, fmt.Errorf("%v: %s", err, out)
	}
	var r struct {
		Count int64 `json:"count"`
	}
	if err := json.Unmarshal([]byte(out), &r); err != nil {
		return 0, err
	}
	return r.Count, nil
}

// storeRoles runs every etcdctl line `port49d store-roles --config cfg
// --broker-config brokerCfg` prints, and then the auth-enabling lines its last comment names, through
// the real etcdctl, as etcd's root does once. It returns one line per
// command run, with its result.
func (e *realEtcd) storeRoles(t *testing.T, cfg, brokerCfg string) []string {
	t.Helper()
	out, err := exec.Command(filepath.Join(root, "bin", "port49d"), "store-roles", "--config", cfg, "--broker-config", brokerCfg).CombinedOutput()
	if err != nil {
		t.Fatalf("port49d store-roles: %v\n%s", err, out)
	}
	var cmds [][]string
	var then string
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "etcdctl "):
			cmds = append(cmds, strings.Fields(line)[1:])
		case strings.HasPrefix(line, "# then, if auth is not enabled yet:"):
			then = strings.TrimPrefix(line, "# then, if auth is not enabled yet:")
		case then != "" && strings.HasPrefix(line, "#"):
			then += " " + strings.TrimSpace(strings.TrimPrefix(line, "#"))
		}
	}
	for _, part := range strings.Split(then, "&&") {
		if f := strings.Fields(part); len(f) > 1 && f[0] == "etcdctl" {
			cmds = append(cmds, f[1:])
		}
	}
	var said []string
	for _, c := range cmds {
		got, err := e.ctl(c...)
		said = append(said, fmt.Sprintf("`etcdctl %s`: %s", strings.Join(c, " "), firstLine(got)))
		if err != nil {
			t.Fatalf("etcdctl %s, as store-roles printed it: %v\n%s", strings.Join(c, " "), err, got)
		}
	}
	return said
}

func TestStoreSnapshotRestore(t *testing.T) {
	bin := os.Getenv("PORT49_LAB_ETCD_BIN")
	if bin == "" {
		t.Skip("PORT49_LAB_ETCD_BIN names no directory holding etcd, etcdctl and etcdutl v3.6.15")
	}
	eachPlatform(t, func(t *testing.T, l *lab) {
		if strings.HasPrefix(l.p.name, "juniper_") {
			t.Skip("the restore is measured on an image that authorizes each command")
		}
		var failed []string
		fail := func(format string, args ...any) { failed = append(failed, fmt.Sprintf(format, args...)) }
		var obs strings.Builder
		row := func(step, what string) { fmt.Fprintf(&obs, "| %s | %s |\n", step, wideCell(what)) }
		obs.WriteString("| step | observed |\n|---|---|\n")

		e := newRealEtcd(t, bin)
		e.start(t, e.data)
		daemonStore := fmt.Sprintf("\nstores:\n  directory:\n    backend: etcd\n    etcd:\n      endpoints: [https://%s]\n      ca_file: %s\n"+
			"      daemon: {cert_file: %s, key_file: %s}\n      hold_ttl: 60s\n", e.client, e.ca, e.daemC, e.daemK)
		brokerStore := fmt.Sprintf("\nstores:\n  directory:\n    backend: etcd\n    etcd:\n      endpoints: [https://%s]\n      ca_file: %s\n"+
			"      broker: {cert_file: %s, key_file: %s}\n      hold_ttl: 60s\n", e.client, e.ca, e.brokC, e.brokK)
		// port49-broker and port49d A on the real member (plan 7e): prepared,
		// not started, because `port49d store-roles` provisions the roles the
		// two processes start under, from the two configs it reads.
		s := l.prepareSplit(t, splitCfg{Store: &splitStore{Daemon: daemonStore, Broker: brokerStore}})
		// The refresh pass is the runner's, and port49d admits from the same
		// file, so touching it swaps the policy on both.
		policyPath := s.Policy
		row("0. `port49d store-roles`, each line run by etcdctl 3.6.15 as root", strings.Join(e.storeRoles(t, s.CfgA, s.CfgBroker), "; "))
		n, err := e.keys("/port49/")
		row("0. the keyspace before the first process starts", fmt.Sprintf("%d keys under /port49/ (err %v)", n, err))
		if err != nil || n != 0 {
			t.Fatalf("the store did not start empty: %d keys, err %v", n, err)
		}

		s.start(t)
		row("0. port49-broker's and port49d's start under those roles", "listening (stores.directory.etcd.roles: enforced, the default)")
		stop := l.capture(t, "L35-restore")
		defer stop()

		sock, _, stopAgent := revokeAgent(t)
		defer stopAgent()
		mint := func(what string) string {
			_, tok := l29Mint(sock, l.p.node)
			if tok == "" {
				t.Fatalf("the agent minted no token (%s)", what)
			}
			return tok
		}
		// Session A: the context's first write, before the snapshot.
		off := l.mark()
		shA, err := l.shell(sliceUser, mint("session A"))
		if err != nil {
			t.Fatalf("SSH login A: %v\nrecords:%s", err, summarize(l.recordsSince(off)))
		}
		defer shA.Close()
		row("1. session A (before the snapshot), `show version`", revokeOutcome(l.p.name, shA, "show version", fail, "A"))

		// The snapshot.
		snap := filepath.Join(t.TempDir(), "snap.db")
		if out, err := e.ctl("snapshot", "save", snap); err != nil {
			t.Fatalf("etcdctl snapshot save: %v\n%s", err, out)
		}
		st, err := exec.Command(filepath.Join(bin, "etcdutl"), "snapshot", "status", snap, "-w", "json").CombinedOutput()
		if err != nil {
			t.Fatalf("etcdutl snapshot status: %v\n%s", err, st)
		}
		var snapStatus struct {
			Revision int64 `json:"revision"`
		}
		if err := json.Unmarshal(st, &snapStatus); err != nil {
			t.Fatalf("etcdutl snapshot status: %v\n%s", err, st)
		}

		// Session B: the same user on the same device, so the same context
		// key, written again after the snapshot. The restore puts A's write
		// back at that key: an earlier write than the last the ledger saw,
		// the rollback design §12 (Backups) names.
		off = l.mark()
		shB, err := l.shell(sliceUser, mint("session B"))
		if err != nil {
			t.Fatalf("SSH login B: %v\nrecords:%s", err, summarize(l.recordsSince(off)))
		}
		defer shB.Close()
		row("2. session B (after the snapshot), `show version`", revokeOutcome(l.p.name, shB, "show version", fail, "B"))
		ctxB, _, _ := ctxIDOf(l.waitForRecords(off, 30*time.Second, func(rs []map[string]any) bool {
			id, _, _ := ctxIDOf(rs, sliceUser)
			return id != ""
		}), sliceUser)
		before, err := e.revision()
		if err != nil {
			t.Fatal(err)
		}
		row("2. revisions", fmt.Sprintf("snapshot at %d; the store at %d before the restore", snapStatus.Revision, before))

		// The restore, under the running port49d.
		errOff := l.errLogSize()
		goneAt := time.Now()
		e.stop()
		args := []string{"snapshot", "restore", snap, "--data-dir", e.restore, "--name", e.name,
			"--initial-cluster", e.name + "=http://" + e.peer, "--initial-advertise-peer-urls", "http://" + e.peer,
			"--bump-revision", "1000000000", "--mark-compacted"}
		if out, err := exec.Command(filepath.Join(bin, "etcdutl"), args...).CombinedOutput(); err != nil {
			t.Fatalf("etcdutl %s: %v\n%s", strings.Join(args, " "), err, out)
		}
		e.start(t, e.restore)
		row("3. the restore", fmt.Sprintf("`etcdutl %s`; the store was gone %s", strings.Join(args[:2], " ")+
			" … --bump-revision 1000000000 --mark-compacted", time.Since(goneAt).Round(100*time.Millisecond)))

		// No revision reused: the restored store's revision, and its next
		// write's, are past every revision the store gave before; a read at
		// one of those is refused as compacted.
		after, err := e.revision()
		if err != nil {
			t.Fatal(err)
		}
		put, err := e.ctl("put", "/port49-restore-probe", "x", "-w", "json")
		if err != nil {
			t.Fatalf("etcdctl put: %v\n%s", err, put)
		}
		var pr struct {
			Header struct {
				Revision int64 `json:"revision"`
			} `json:"header"`
		}
		json.Unmarshal([]byte(put), &pr)
		old, oldErr := e.ctl("get", "/port49-restore-probe", "--rev", strconv.FormatInt(before, 10))
		e.ctl("del", "/port49-restore-probe")
		row("3. revisions after the restore", fmt.Sprintf("the store at %d; the next write at %d; a read at %d: %s (err %v)",
			after, pr.Header.Revision, before, firstLine(old), oldErr))
		if after <= before || pr.Header.Revision <= before {
			fail("the restore reused revisions: the store at %d and its next write at %d, after %d before it",
				after, pr.Header.Revision, before)
		}
		if oldErr == nil || !strings.Contains(old, "compacted") {
			fail("a read at a revision from before the restore was not refused as compacted: %s", old)
		}

		// What port49d said, and session B's next command: the ledger has
		// B's write at a revision past the restored record's.
		time.Sleep(15 * time.Second)
		row("4. port49d's lines since the restore", strings.Join(append(append(l.errLinesSince(errOff, "store"),
			l.errLinesSince(errOff, "ledger")...), l.errLinesSince(errOff, "listening on")...), " / "))
		dark := len(l.errLinesSince(errOff, "closing every listener")) > 0
		if dark {
			if err := l.listenAgain(errOff, 150*time.Second); err != nil {
				t.Fatalf("after the restore: %v", err)
			}
		}
		off = l.mark()
		bOut := revokeOutcome(l.p.name, shB, "show version", fail, "B after the restore")
		recs := l.waitForRecords(off, 30*time.Second, func(rs []map[string]any) bool {
			id, _, _ := ctxIDOf(rs, sliceUser)
			return id != ""
		})
		_, v, r := ctxIDOf(recs, sliceUser)
		row("4. session B's next command", fmt.Sprintf("%s; record %s %s (B's ctx_id %s)", bOut, v, r, ctxB))
		if !dark && (v != "deny" || r != "store_unavailable") {
			fail("a context written since the snapshot was not denied store_unavailable: %s %s", v, r)
		}

		// The next refresh pass: touching the policy swaps it.
		errOff = l.errLogSize()
		f, err := os.OpenFile(policyPath, os.O_WRONLY|os.O_APPEND, 0)
		if err != nil {
			t.Fatal(err)
		}
		fmt.Fprintf(f, "\n# touched after the restore (L35 restore, %s)\n", time.Now().UTC().Format(time.RFC3339))
		f.Close()
		for deadline := time.Now().Add(60 * time.Second); time.Now().Before(deadline) &&
			len(l.errLinesSince(errOff, "policy refresh")) == 0; {
			time.Sleep(time.Second)
		}
		refreshed := append(l.errLinesSince(errOff, "policy"), l.errLinesSince(errOff, "will not open")...)
		row("5. the refresh pass after touching the policy", strings.Join(refreshed, " / "))
		recs = l.recordsSince(off)
		row("5. records since the restore", summarize(recs))
		revoked := false
		for _, rec := range recs {
			if rec["event"] == "refresh" && rec["verdict"] == "deny" {
				if s, _ := rec["session"].(map[string]any); s != nil && s["username"] == sliceUser {
					revoked = true
				}
			}
		}
		if !revoked && !dark {
			fail("the refresh pass did not revoke the context written since the snapshot")
		}
		off = l.mark()
		bAgain := revokeOutcome(l.p.name, shB, "show version", func(string, ...any) {}, "B after the refresh")
		row("5. session B's next command after the pass", fmt.Sprintf("%s; records %v", bAgain,
			reasonsOf(l.waitForRecords(off, 30*time.Second, func(rs []map[string]any) bool {
				return len(reasonsOf(rs, "authorize_command")) > 0
			}), "authorize_command")))

		// A new login works: it replaces the restored record (design §12).
		off = l.mark()
		outs, lerr := l.loginWithin(sliceUser, mint("after the restore"), 60*time.Second, "show version")
		recs = l.waitForRecords(off, 20*time.Second, func(rs []map[string]any) bool {
			return len(reasonsOf(rs, "authorize_session")) > 0 && len(reasonsOf(rs, "authorize_command")) > 0
		})
		row("6. a new token login after the restore, `show version`", fmt.Sprintf("login err %v; printed %s; "+
			"redeem %v, authorize_session %v, authorize_command %v", lerr, firstOut(outs), reasonsOf(recs, "redeem"),
			reasonsOf(recs, "authorize_session"), reasonsOf(recs, "authorize_command")))
		if lerr != nil {
			fail("a new login after the restore failed: %v", lerr)
		}
		if !contains(reasonsOf(recs, "authorize_session"), "permit context_matched") {
			fail("the new login's session was not answered from its own context: %v", reasonsOf(recs, "authorize_session"))
		}
		if !contains(reasonsOf(recs, "authorize_command"), "permit permit_dominates") {
			fail("the new login's command was not permitted: %v", reasonsOf(recs, "authorize_command"))
		}

		note := obs.String()
		if len(failed) > 0 {
			note += "\n**Failed:**\n\n- " + strings.Join(failed, "\n- ") + "\n"
		}
		l.result(t, "L35-restore", restoreClaim, note)
		if len(failed) > 0 {
			t.Fatalf("L35 restore on %s: %s", l.p.name, strings.Join(failed, "; "))
		}
	})
}
