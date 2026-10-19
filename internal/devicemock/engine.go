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
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/rhwendt/port49/internal/tacacs/wire"
)

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

// errConn marks a dial, handshake, write or read failure.
var errConn = errors.New("devicemock: connection failure")

// connErr names a connection failure by its step and class event. Its text
// carries the transport's own error, which holds no packet content.
type connErr struct {
	Step, Event string
	Err         error
}

func (e *connErr) Error() string {
	return fmt.Sprintf("devicemock: %s: %s (%v)", e.Step, e.Event, e.Err)
}
func (e *connErr) Is(target error) bool { return target == errConn }
func (e *connErr) Unwrap() error        { return e.Err }

const ioTimeout = 30 * time.Second

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
	if len(p.Stimulus.Steps) == 0 {
		return Transcript{}, errors.New("devicemock: the profile has no steps")
	}
	pl := &player{p: p, t: t, l: l, now: time.Now()}
	pl.tr.Scenario = scenario
	defer pl.closeConn()
	steps := p.Stimulus.Steps[:len(PlayedSteps(p, scenario))]
	switch BaseScenario(scenario) {
	case "wrong_credential":
		bogus := make([]byte, 24)
		if _, err := rand.Read(bogus); err != nil {
			return pl.tr, err
		}
		pl.l.Credential = []byte(hex.EncodeToString(bogus))
	case "unknown_ca": // tls_unknown_ca
		// A TLS 1.3 client's Handshake returns nil once it has written its
		// Finished, before port49 judges the certificate, so the refusal is
		// observed on the login that follows: a received alert, or the reset
		// port49 sends after it (which races the alert). Either is the class
		// event tls_refused.
		res, err := pl.step(ctx, steps[0])
		if err != nil {
			outcome, ok := pl.refusal(steps[0].Name, err)
			if !ok {
				// A timeout or any other failure is not a refusal.
				return pl.tr, err
			}
			return pl.end(outcome, StepResult{Step: steps[0].Name, Event: "tls_refused", Conn: pl.nconns}), nil
		}
		pl.tr.Steps = append(pl.tr.Steps, res)
		return pl.end("handshake_ok"), nil
	}
	for _, s := range steps {
		res, err := pl.step(ctx, s)
		if err != nil {
			if outcome, ok := pl.refusal(s.Name, err); ok {
				return pl.end(outcome, StepResult{Step: s.Name, Event: handshakeEvent(err), Conn: pl.nconns}), nil
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
		case "send_credential":
			return pl.tr, fmt.Errorf("devicemock: %s: send_credential answered twice", s.Name)
		default:
			return pl.end(r.Outcome), nil
		}
	}
	return pl.end("login_ok"), nil
}

// refusal reports whether err is the device being refused (an alert, a reset
// or a close) and how the play ends: as the profile's reaction to that event
// says, else handshake_refused. A timeout is never a refusal.
func (pl *player) refusal(step string, err error) (string, bool) {
	ev := handshakeEvent(err)
	if !errors.Is(err, errConn) || !isRefusal(ev) {
		return "", false
	}
	if r, ok := pl.p.RefusalReaction(step, ev); ok && r.Outcome != "" {
		return r.Outcome, true
	}
	return "handshake_refused", true
}

func (pl *player) end(outcome string, extra ...StepResult) Transcript {
	pl.tr.Steps = append(pl.tr.Steps, extra...)
	pl.tr.Outcome, pl.tr.Conns = outcome, pl.nconns
	return pl.tr
}

// PlayedSteps is the step names Play plays for a scenario, in order:
// token_login, tls_token_login and single_connection play every stimulus
// step; wrong_credential, store_unavailable, tls_store_unavailable,
// flight_delay and tls_unknown_ca play login alone. Play uses it, and
// genprofile builds goldens to it, so the two cannot disagree.
func PlayedSteps(p *Profile, scenario string) []string {
	if len(p.Stimulus.Steps) == 0 {
		return nil
	}
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

func (pl *player) closeConn() {
	if pl.c != nil {
		pl.c.Close()
		pl.c = nil
	}
}

func (pl *player) scaled(d time.Duration) time.Duration {
	return time.Duration(float64(d) * pl.t.Scale)
}

func (pl *player) dial(ctx context.Context) error {
	d := &net.Dialer{}
	if pl.t.LocalAddr != "" {
		ip := net.ParseIP(pl.t.LocalAddr)
		if ip == nil {
			return fmt.Errorf("devicemock: local address %q is not an IP", pl.t.LocalAddr)
		}
		d.LocalAddr = &net.TCPAddr{IP: ip}
	}
	c, err := d.DialContext(ctx, "tcp", pl.t.Addr)
	if err != nil {
		return err
	}
	pl.nconns++
	if pl.t.Transport == "tls" {
		if pl.p.Stimulus.TLS == nil || pl.t.TLS == nil {
			c.Close()
			return errors.New("devicemock: a tls play needs the profile's stimulus.tls and the target's TLS material")
		}
		// The device's measured delay holds on every connection it makes.
		c = DelayFlight(c, pl.scaled(pl.p.Stimulus.TLS.FlightDelay), pl.t.Sleep)
		tc := tls.Client(c, SessionConfig(pl.p.Stimulus.TLS, *pl.t.TLS))
		hctx, cancel := context.WithTimeout(ctx, ioTimeout)
		defer cancel()
		if err := tc.HandshakeContext(hctx); err != nil {
			c.Close()
			return err
		}
		c = tc
	}
	pl.c = c
	return nil
}

func (pl *player) deadline(ctx context.Context) time.Time {
	dl := time.Now().Add(ioTimeout)
	if cd, ok := ctx.Deadline(); ok && cd.Before(dl) {
		dl = cd
	}
	return dl
}

func (pl *player) send(h wire.Header, body []byte) error {
	if pl.t.Transport == "tls" {
		h.Flags |= wire.FlagUnencrypted
	} else {
		body = wire.Obfuscate(h, pl.t.Key, body)
	}
	h.Length = uint32(len(body))
	_, err := pl.c.Write(append(h.Encode(), body...))
	return err
}

// recv reads one reply and returns its header and clear body.
func (pl *player) recv() (wire.Header, []byte, error) {
	var hb [wire.HeaderLen]byte
	if _, err := io.ReadFull(pl.c, hb[:]); err != nil {
		return wire.Header{}, nil, err
	}
	h, err := wire.DecodeHeader(hb[:])
	if err != nil {
		return h, nil, err
	}
	if h.Length > wire.MaxBodyLen {
		return h, nil, fmt.Errorf("reply body length %d over the ceiling", h.Length)
	}
	body := make([]byte, h.Length)
	if _, err := io.ReadFull(pl.c, body); err != nil {
		return h, nil, err
	}
	// RFC 9887 §4: the unencrypted flag is set over TLS and never over 49.
	switch unenc := h.Flags&wire.FlagUnencrypted != 0; {
	case pl.t.Transport == "tls" && !unenc:
		return h, nil, errors.New("reply obfuscated over tls")
	case pl.t.Transport != "tls" && unenc:
		return h, nil, errors.New("reply unencrypted over tcp")
	case !unenc:
		body = wire.Obfuscate(h, pl.t.Key, body)
	}
	return h, body, nil
}

func (pl *player) step(ctx context.Context, s Step) (StepResult, error) {
	fail := func(err error) (StepResult, error) {
		pl.closeConn()
		var ce *connErr
		if errors.As(err, &ce) {
			return StepResult{}, err
		}
		return StepResult{}, &connErr{Step: s.Name, Event: handshakeEvent(err), Err: err}
	}
	if !pl.reuse || pl.c == nil {
		pl.closeConn()
		if err := pl.dial(ctx); err != nil {
			return fail(err)
		}
	}
	if err := pl.c.SetDeadline(pl.deadline(ctx)); err != nil {
		return fail(err)
	}
	var sid [4]byte
	if _, err := rand.Read(sid[:]); err != nil {
		return StepResult{}, err
	}
	h := wire.Header{MajorVersion: wire.MajorVersion, MinorVersion: s.MinorVersion, SeqNo: 1,
		SessionID: binary.BigEndian.Uint32(sid[:])}
	if BaseScenario(pl.tr.Scenario) == "single_connection" || pl.p.Stimulus.Connections.SingleConnectFlag {
		h.Flags |= wire.FlagSingleConnect
	}
	code := func(field, name string) uint8 { return Codes[field][name] }
	var body []byte
	switch s.Type {
	case "authen":
		h.Type = wire.TypeAuthen
		st := wire.AuthenStart{Action: code("action", s.Fields.Action), PrivLvl: s.Fields.PrivLvl,
			AuthenType: code("authen_type", s.Fields.AuthenType), Service: code("service", s.Fields.Service),
			User: []byte(pl.l.User), Port: []byte(s.Port), RemAddr: []byte(pl.l.RemAddr)}
		if s.Fields.AuthenType == "pap" {
			st.Data = pl.l.Credential
		}
		body = st.Encode()
	case "author":
		h.Type = wire.TypeAuthor
		body = wire.AuthorRequest{AuthenMethod: code("authen_method", s.Fields.AuthenMethod), PrivLvl: s.Fields.PrivLvl,
			AuthenType: code("authen_type", s.Fields.AuthenType), Service: code("service", s.Fields.Service),
			User: []byte(pl.l.User), Port: []byte(s.Port), RemAddr: []byte(pl.l.RemAddr), Args: pl.expand(s.Args)}.Encode()
	case "acct":
		h.Type = wire.TypeAcct
		body = wire.AcctRequest{Flags: acctFlag(s.Flags), AuthenMethod: code("authen_method", s.Fields.AuthenMethod),
			PrivLvl: s.Fields.PrivLvl, AuthenType: code("authen_type", s.Fields.AuthenType), Service: code("service", s.Fields.Service),
			User: []byte(pl.l.User), Port: []byte(s.Port), RemAddr: []byte(pl.l.RemAddr), Args: pl.expand(s.Args)}.Encode()
	default:
		return StepResult{}, fmt.Errorf("devicemock: step %s has type %q", s.Name, s.Type)
	}
	h.Length = uint32(len(body))
	if err := pl.send(h, body); err != nil {
		return fail(err)
	}
	rh, rb, err := pl.recv()
	if err != nil {
		return fail(err)
	}
	if rh.Type != h.Type || rh.SeqNo != h.SeqNo+1 || rh.SessionID != h.SessionID {
		pl.closeConn()
		return StepResult{}, fmt.Errorf("devicemock: %s: the reply does not answer the request (type, sequence or session)", s.Name)
	}
	res := StepResult{Step: s.Name, Conn: pl.nconns, SingleConnect: rh.Flags&wire.FlagSingleConnect != 0}
	for {
		switch h.Type {
		case wire.TypeAuthen:
			r, err := wire.DecodeAuthenReply(rb)
			if err != nil {
				pl.closeConn()
				return StepResult{}, fmt.Errorf("devicemock: %s: undecodable authen reply: %w", s.Name, err)
			}
			res.Event, res.ServerMsgLen = authenEvent(r.Status), len(r.ServerMsg)
			// A GETPASS (or other prompt) the profile answers with the
			// credential is answered within the step.
			if re, rerr := pl.p.React(s.Name, res.Event); rerr == nil && re.Then == "send_credential" && h.SeqNo == 1 {
				h.SeqNo += 2
				cont := wire.AuthenContinue{UserMsg: pl.l.Credential}.Encode()
				if err := pl.send(h, cont); err != nil {
					return fail(err)
				}
				if rh, rb, err = pl.recv(); err != nil {
					return fail(err)
				}
				if rh.Type != h.Type || rh.SeqNo != h.SeqNo+1 || rh.SessionID != h.SessionID {
					pl.closeConn()
					return StepResult{}, fmt.Errorf("devicemock: %s: the reply does not answer the continue", s.Name)
				}
				res.SingleConnect = res.SingleConnect || rh.Flags&wire.FlagSingleConnect != 0
				continue
			}
		case wire.TypeAuthor:
			r, err := wire.DecodeAuthorResponse(rb)
			if err != nil {
				pl.closeConn()
				return StepResult{}, fmt.Errorf("devicemock: %s: undecodable author reply: %w", s.Name, err)
			}
			res.Event, res.ServerMsgLen = authorEvent(r.Status), len(r.ServerMsg)
			for _, a := range r.Args {
				res.Args = append(res.Args, string(a))
			}
			if s.Name == "authorize_session" || s.Name == "command_permitted" {
				gate, warn := Check(pl.p.Acceptance, s.Name, r.Args)
				pl.tr.Gate = append(pl.tr.Gate, gate...)
				pl.tr.Warn = append(pl.tr.Warn, warn...)
			}
		case wire.TypeAcct:
			r, err := wire.DecodeAcctReply(rb)
			if err != nil {
				pl.closeConn()
				return StepResult{}, fmt.Errorf("devicemock: %s: undecodable acct reply: %w", s.Name, err)
			}
			res.Event, res.ServerMsgLen = acctEvent(r.Status), len(r.ServerMsg)
		}
		break
	}
	if !(res.SingleConnect && h.Flags&wire.FlagSingleConnect != 0) {
		pl.closeConn()
		pl.reuse = false
	}
	return res, nil
}

func acctFlag(f string) uint8 {
	switch f {
	case "start":
		return wire.AcctFlagStart
	case "stop":
		return wire.AcctFlagStop
	case "watchdog":
		return wire.AcctFlagWatchdog
	}
	return 0
}

func authenEvent(s uint8) string {
	switch s {
	case wire.AuthenStatusPass:
		return "authen_pass"
	case wire.AuthenStatusFail:
		return "authen_fail"
	case wire.AuthenStatusGetPass:
		return "authen_getpass"
	case wire.AuthenStatusGetUser:
		return "authen_getuser"
	case wire.AuthenStatusGetData:
		return "authen_getdata"
	case wire.AuthenStatusError:
		return "authen_error"
	}
	return "authen_status_" + strconv.Itoa(int(s))
}

func authorEvent(s uint8) string {
	switch s {
	case wire.AuthorStatusPassAdd:
		return "author_pass_add"
	case wire.AuthorStatusPassRepl:
		return "author_pass_repl"
	case wire.AuthorStatusFail:
		return "author_fail"
	case wire.AuthorStatusError:
		return "author_error"
	}
	return "author_status_" + strconv.Itoa(int(s))
}

func acctEvent(s uint8) string {
	switch s {
	case wire.AcctStatusSuccess:
		return "acct_success"
	case wire.AcctStatusError:
		return "acct_error"
	}
	return "acct_status_" + strconv.Itoa(int(s))
}

// expand fills a step's argument templates. It never puts the credential
// into an argument.
func (pl *player) expand(args []string) [][]byte {
	r := strings.NewReplacer("{user}", pl.l.User, "{rem_addr}", pl.l.RemAddr,
		"{task_id}", strconv.FormatInt(pl.now.UnixNano()%100000, 10),
		"{start_time}", strconv.FormatInt(pl.now.Unix(), 10), "{stop_time}", strconv.FormatInt(pl.now.Unix(), 10))
	out := make([][]byte, len(args))
	for i, a := range args {
		out[i] = []byte(r.Replace(a))
	}
	return out
}

// handshakeEvent names a connection failure as a class event. A received
// alert arrives as a *net.OpError with Op "remote error" whose text is
// "tls: <description>" (tls.AlertError is QUIC's type and never matches).
func handshakeEvent(err error) string {
	var ce *connErr
	if errors.As(err, &ce) {
		return ce.Event
	}
	var op *net.OpError
	if errors.As(err, &op) && op.Op == "remote error" && op.Err != nil {
		switch strings.TrimPrefix(op.Err.Error(), "tls: ") {
		case "bad certificate":
			return "alert_bad_certificate"
		case "unknown certificate authority":
			return "alert_unknown_ca"
		case "expired certificate":
			return "alert_certificate_expired"
		case "handshake failure":
			return "alert_handshake_failure"
		}
		return "alert_other"
	}
	var ne net.Error
	switch {
	case errors.Is(err, syscall.ECONNRESET), errors.Is(err, syscall.EPIPE):
		return "conn_reset"
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		return "conn_closed"
	case errors.Is(err, os.ErrDeadlineExceeded), errors.Is(err, context.DeadlineExceeded), errors.As(err, &ne) && ne.Timeout():
		return "handshake_timeout"
	}
	return "conn_error"
}

func isRefusal(event string) bool {
	return strings.HasPrefix(event, "alert_") || event == "conn_reset" || event == "conn_closed"
}

// String prints one line per step, then the outcome, then the gates and
// warnings by rule id and detail. It is the only form tests print.
func (tr Transcript) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "scenario %s\n", tr.Scenario)
	for _, s := range tr.Steps {
		fmt.Fprintf(&b, "  %s %s args=%q server_msg=%d bytes conn=%d\n", s.Step, s.Event, s.Args, s.ServerMsgLen, s.Conn)
	}
	fmt.Fprintf(&b, "outcome %s conns=%d\n", tr.Outcome, tr.Conns)
	for _, v := range tr.Gate {
		fmt.Fprintf(&b, "  gate %s (%s): %s\n", v.Rule, v.Effect, v.Detail)
	}
	for _, v := range tr.Warn {
		fmt.Fprintf(&b, "  warn %s: %s\n", v.Rule, v.Detail)
	}
	return b.String()
}
