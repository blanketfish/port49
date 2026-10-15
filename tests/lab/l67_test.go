//go:build lab

package lab

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/rhwendt/port49/internal/broker/api"
	"github.com/rhwendt/port49/internal/directory"
	"github.com/rhwendt/port49/internal/testpki"
	"github.com/rhwendt/port49/internal/totp"
)

// L67 (plan 9e; spec §13 decision 47 rulings 6 and 7, D2, D5; §15 L67): what a
// directory answers a person's simple bind, in every state an account can be
// in, and how the directory-password sign-in behaves against it. It runs on
// OpenLDAP and Samba AD as containers (TestL67) and on the Windows DC
// (TestL67Windows, the L44 harness). Every cell has its positive control first.

const l67Claim = "A person's simple bind and port49's directory-password sign-in (plan 9e; policy engine spec §13 decision 47 " +
	"rulings 6 and 7, D2 and D5; §15 L67): (a) `CheckPassword` binds a person over LDAPS and over StartTLS, and what a wrong " +
	"password answers; (b) an unauthenticated bind is what RFC 4513 §5.1.2 warns it is, and `CheckPassword` with an empty " +
	"password never opens a connection; (c) what a bind answers for an expired, a must-change, a disabled and a locked " +
	"account, with the right password and with a wrong one, and whether the state shows without the password; (d) the " +
	"directory's failed-password count after six sign-ins with a wrong password through a broker at port49's default limits " +
	"(the sixth throttled, no bind) and after nine across a window boundary against the directory's lockout threshold of ten; " +
	"(e) a wrong code is refused before the directory is asked; (f) the creation time the sign-in reads; and (g) the " +
	"sign-in end to end, `login --directory` enrolling, `token` minting, and the directory stopped, on the compose stack's " +
	"broker on etcd and on port49d on the memory store."

// The numbers of cells (d) and the lockout they are measured against.
const (
	// l67Threshold is the lockout threshold the lab sets on every directory:
	// Active Directory's, Samba's and the ppolicy overlay's pwdMaxFailure.
	l67Threshold = 10
	// l67Defaults is how many wrong passwords a default-limits broker lets
	// reach the directory for one principal (oidc.DefaultFailuresPerPrincipal);
	// the next is throttled. The cell sends one more.
	l67Defaults = 5
	// l67Before and l67After are the nine wrong passwords across a window
	// boundary: four before it ends, five after (I11), one under l67Threshold.
	l67Before, l67After = 4, 5
	// l67Window is rate_limits.window for the straddle.
	l67Window = 2 * time.Minute
)

// l67Cell is one cell of the plan's table.
type l67Cell struct{ ID, Name, Claim string }

// l67Cells is the table the harness runs, in the plan's order.
var l67Cells = []l67Cell{
	{"a", "check_password", "CheckPassword binds a person with the right password over LDAPS and StartTLS, after the broker's own bind; a wrong one is a PasswordRefusal"},
	{"b", "empty_password", "an unauthenticated bind is recorded, and CheckPassword with an empty password sends nothing (the server's connection count is unchanged)"},
	{"c", "account_states", "an expired, must-change, disabled and locked account answers a bind with the right and a wrong password"},
	{"d", "attempt_limits", "six wrong passwords at the default limits reach the directory five times; nine across a window boundary do not lock"},
	{"e", "wrong_code", "a wrong code is sign_in_refused and the directory's failed count does not move"},
	{"f", "created_at", "SignInEntry reads a creation time within a minute of the seed"},
	{"g", "end_to_end", "login --directory enrols, token mints, and with the directory stopped token mints from grace and login exits 1"},
}

// ---------------------------------------------------------------------------
// Passwords, steps and results: the parts a unit test holds.
// ---------------------------------------------------------------------------

// l67Password is the run's person password: "Aa1+" (the four classes Samba's
// and Windows' complexity rule want) and 20 base64 characters from crypto/rand,
// 24 in all. None of its characters is one a shell, sed, an env file or
// PowerShell would read. It is held in memory and written nowhere but the
// directories' environment.
func l67Password() (string, error) {
	b := make([]byte, 15)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "Aa1+" + base64.RawStdEncoding.EncodeToString(b), nil
}

// l67NextStep is the TOTP step the next sign-in of a person whose last taken
// step is last can use, and how long to wait before the broker's clock is
// within totp.Window of it. A step is taken once, in increasing order.
func l67NextStep(last int64, now time.Time) (int64, time.Duration) {
	period := int64(totp.Period / time.Second)
	cur := now.Unix() / period
	step := max(last+1, cur-totp.Window)
	if step <= cur+totp.Window {
		return step, 0
	}
	return step, time.Unix((step-totp.Window)*period, 0).Sub(now)
}

// l67CodeAt is the authenticator's code for a step.
func l67CodeAt(secret []byte, step int64) (string, error) {
	return totp.Code(secret, time.Unix(step*int64(totp.Period/time.Second), 0))
}

// l67WrongCode is a well-formed code the broker reads as no step at all: it
// matches none within totp.SkewReach of now, so it is neither a skew nor a
// replay.
func l67WrongCode(secret []byte, now time.Time) (string, error) {
	cur := now.Unix() / int64(totp.Period/time.Second)
	for step := cur + 40; ; step++ {
		code, err := l67CodeAt(secret, step)
		if err != nil {
			return "", err
		}
		if _, err := totp.Check(secret, code, now, 0); errors.Is(err, totp.ErrWrongCode) {
			return code, nil
		}
	}
}

// l67Unchanged is whether an action left a server-side count alone. base is
// what reading the count costs (a Windows reader's own ssh is a TCP
// connection the DC accepts; a log read costs nothing).
func l67Unchanged(before, after, base int) bool { return after-before == base }

// l67Result is a bind's outcome as the evidence keeps it: what kind it was,
// the LDAP result and the diagnostic data (AD's code, or ppolicy's error).
type l67Result struct {
	Kind   string
	Result int
	Data   string
}

var l67ADData = regexp.MustCompile(`\bdata ([0-9a-f]{3,4})\b`)

// l67Classify is err as an l67Result. Kinds: ok, refused (a *PasswordRefusal),
// empty_password, unavailable, ldap (a raw go-ldap error), error.
func l67Classify(err error) l67Result {
	var pr *directory.PasswordRefusal
	var le *ldap.Error
	switch {
	case err == nil:
		return l67Result{Kind: "ok"}
	case errors.As(err, &pr):
		return l67Result{Kind: "refused", Result: pr.Result, Data: pr.Data}
	case errors.Is(err, directory.ErrEmptyPassword):
		return l67Result{Kind: "empty_password"}
	case errors.Is(err, directory.ErrUnavailable):
		return l67Result{Kind: "unavailable"}
	case errors.As(err, &le):
		if le.ResultCode == 0 {
			return l67Result{Kind: "ok"}
		}
		r := l67Result{Kind: "ldap", Result: int(le.ResultCode)}
		if le.Err != nil {
			if m := l67ADData.FindStringSubmatch(le.Err.Error()); m != nil {
				r.Data = m[1]
			}
		}
		return r
	}
	return l67Result{Kind: "error"}
}

// l67Record writes one check's result to the evidence: the kind, the LDAP
// result code and the diagnostic data. The log scrubs the password (hide).
func l67Record(ev *evidenceLog, label string, err error) {
	r := l67Classify(err)
	code := r.Result
	line := evidenceLine{Event: "l67_" + r.Kind, Label: label, ResultCode: &code, Data: r.Data}
	if err != nil {
		line.Error = oneLineMax(err.Error(), 300)
	}
	ev.add(line)
}

// show is a result as a table cell says it.
func (r l67Result) show() string {
	s := r.Kind
	if r.Kind == "refused" || r.Kind == "ldap" {
		s += fmt.Sprintf(" (LDAP result %d", r.Result)
		if r.Data != "" {
			s += ", data " + r.Data
		}
		s += ")"
	}
	return s
}

// ---------------------------------------------------------------------------
// The directory under test: its own view of an account.
// ---------------------------------------------------------------------------

// l67State is an account as the directory itself reports it: the control that
// says the account is in the state a cell means.
type l67State struct {
	Count                                 int // failed-password count: pwdFailureTime values, badPwdCount
	Locked, Expired, Disabled, MustChange bool
	Created                               time.Time
}

func (s l67State) String() string {
	return fmt.Sprintf("failed %d, locked %v, expired %v, disabled %v, must_change %v", s.Count, s.Locked, s.Expired, s.Disabled, s.MustChange)
}

// l67X is one directory's run: the cells share its evidence, its rows and its
// failures, and write the note when they are done.
type l67X struct {
	t      *testing.T
	owner  *testing.T // the directory's own test: what outlives the cells
	d      *directories
	dir    *labDir
	pw     string // the people's password: never printed
	ev     *evidenceLog
	rows   []string
	failed []string
	limits []string // what this directory could not be put in or asked
	broker *l67Broker
	people map[string]*l67Person
	seedAt time.Time
}

func (x *l67X) row(id, format string, args ...any) {
	x.rows = append(x.rows, fmt.Sprintf("| %s | %s |", id, wideCell(x.ev.scrub(fmt.Sprintf(format, args...)))))
}

func (x *l67X) fail(format string, args ...any) {
	x.failed = append(x.failed, x.ev.scrub(fmt.Sprintf(format, args...)))
}

func (x *l67X) limit(format string, args ...any) {
	x.limits = append(x.limits, x.ev.scrub(fmt.Sprintf(format, args...)))
}

// resolver is the broker's resolver on via, in the sign-in's shape: the broker's
// simple bind and no certificate mapping.
func (x *l67X) resolver(t *testing.T, via *labDir) *directory.Resolver {
	t.Helper()
	cfg := via.config("direct", via.groupsBaseDN, via.bindSimple(), sanEmail())
	return via.resolverWith(t, cfg, x.d.password, nil)
}

// entry is user's sign-in entry through the broker's bind. A failure is the
// harness's: INVALID, not a measurement.
func (x *l67X) entry(t *testing.T, via *labDir, user string) directory.SignInEntry {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	e, err := x.resolver(t, via).SignInEntry(ctx, user, "")
	if err != nil {
		t.Fatalf("INVALID: %s: the broker's bind could not read %s: %v", x.dir.name, user, err)
	}
	return e
}

// check is CheckPassword as the sign-in calls it, recorded.
func (x *l67X) check(t *testing.T, r *directory.Resolver, e directory.SignInEntry, label, password string) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	err := r.CheckPassword(ctx, e.Server, e.DN, password)
	l67Record(x.ev, label, err)
	return err
}

func (x *l67X) wrong() string { return x.pw + "x" }

// state reads user's account from the directory's own attributes.
func (x *l67X) state(t *testing.T, user string) (l67State, error) {
	t.Helper()
	switch x.dir.name {
	case platOpenLDAP:
		return x.ldapState(user)
	case platSamba:
		return x.sambaState(t, user)
	}
	var out struct {
		Enabled         bool   `json:"enabled"`
		LockedOut       bool   `json:"locked_out"`
		PasswordExpired bool   `json:"password_expired"`
		MustChange      bool   `json:"must_change"`
		BadPwdCount     int    `json:"bad_pwd_count"`
		WhenCreated     string `json:"when_created"`
	}
	if err := x.dir.win.try(t, "l67", map[string]any{"step": "state", "name": user}, 5*time.Minute, &out); err != nil {
		return l67State{}, err
	}
	s := l67State{Count: out.BadPwdCount, Locked: out.LockedOut, Expired: out.PasswordExpired && !out.MustChange,
		Disabled: !out.Enabled, MustChange: out.MustChange}
	s.Created, _ = time.Parse(time.RFC3339Nano, out.WhenCreated)
	return s, nil
}

// ldapAttrs reads attrs of user's entry as the broker's account, over LDAPS.
func (x *l67X) ldapAttrs(user string, attrs ...string) (*ldap.Entry, error) {
	cfg, err := x.dir.d.pki.clientTLS(x.dir.uri)
	if err != nil {
		return nil, err
	}
	c, err := ldap.DialURL(x.dir.uri, ldap.DialWithTLSConfig(cfg))
	if err != nil {
		return nil, err
	}
	defer c.Close()
	if err := c.Bind(x.dir.bindDN, x.dir.d.password); err != nil {
		return nil, err
	}
	res, err := c.Search(ldap.NewSearchRequest(x.dir.baseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 2, 30, false,
		fmt.Sprintf("(&%s(%s=%s))", x.dir.userFilter, x.dir.usernameAttr, ldap.EscapeFilter(user)), attrs, nil))
	if err != nil {
		return nil, err
	}
	if len(res.Entries) != 1 {
		return nil, fmt.Errorf("%d entries for %s", len(res.Entries), user)
	}
	return res.Entries[0], nil
}

// ldapState is OpenLDAP's: the ppolicy overlay's operational attributes.
func (x *l67X) ldapState(user string) (l67State, error) {
	e, err := x.ldapAttrs(user, "pwdFailureTime", "pwdAccountLockedTime", "pwdChangedTime", "pwdReset", "createTimestamp")
	if err != nil {
		return l67State{}, err
	}
	const gen = "20060102150405Z"
	s := l67State{Count: len(e.GetAttributeValues("pwdFailureTime"))}
	locked := e.GetAttributeValue("pwdAccountLockedTime")
	s.Disabled = locked == "000001010000Z" // locked until an administrator unlocks it
	s.Locked = locked != "" && !s.Disabled
	s.MustChange = e.GetAttributeValue("pwdReset") == "TRUE"
	if changed, err := time.Parse(gen, e.GetAttributeValue("pwdChangedTime")); err == nil {
		s.Expired = changed.Add(90 * 24 * time.Hour).Before(time.Now()) // pwdMaxAge in seed.ldif
	}
	s.Created, _ = time.Parse(gen, e.GetAttributeValue("createTimestamp"))
	return s, nil
}

// sambaState reads the DC's own database: ldbsearch on sam.ldb, which computes
// msDS-User-Account-Control-Computed (0x10 locked out, 0x800000 password expired).
func (x *l67X) sambaState(t *testing.T, user string) (l67State, error) {
	out, err := x.dir.exec("ldbsearch", "-H", "/var/lib/samba/private/sam.ldb", "(sAMAccountName="+user+")",
		"badPwdCount", "userAccountControl", "pwdLastSet", "whenCreated", "msDS-User-Account-Control-Computed")
	if err != nil {
		return l67State{}, fmt.Errorf("ldbsearch: %v: %s", err, oneLineMax(out, 200))
	}
	attrs := map[string]string{}
	for _, ln := range strings.Split(out, "\n") {
		if k, v, ok := strings.Cut(strings.TrimRight(ln, "\r"), ": "); ok && !strings.HasPrefix(k, "#") {
			attrs[k] = v
		}
	}
	num := func(k string) int64 { n, _ := strconv.ParseInt(attrs[k], 10, 64); return n }
	if _, ok := attrs["badPwdCount"]; !ok && num("userAccountControl") == 0 {
		return l67State{}, fmt.Errorf("ldbsearch found no account %s", user)
	}
	computed := num("msDS-User-Account-Control-Computed")
	s := l67State{Count: int(num("badPwdCount")), Disabled: num("userAccountControl")&2 != 0,
		MustChange: attrs["pwdLastSet"] == "0", Locked: computed&0x10 != 0, Expired: computed&0x800000 != 0 && attrs["pwdLastSet"] != "0"}
	s.Created, _ = time.Parse("20060102150405.0Z", attrs["whenCreated"])
	return s, nil
}

// conns is how many connections the directory has accepted, read where the
// directory keeps the count.
func (x *l67X) conns(t *testing.T) (int, error) {
	t.Helper()
	switch x.dir.name {
	case platOpenLDAP:
		b, err := x.dir.d.dockerCompose("logs", "--no-color", x.dir.service).CombinedOutput()
		if err != nil {
			return 0, fmt.Errorf("compose logs: %v", err)
		}
		return strings.Count(string(b), " ACCEPT from "), nil
	case platSamba:
		out, err := x.dir.exec("cat", "/proc/net/snmp")
		if err != nil {
			return 0, err
		}
		return l67PassiveOpens(out)
	}
	var out struct {
		Accepted int64 `json:"accepted"`
	}
	if err := x.dir.win.try(t, "l67", map[string]any{"step": "connections"}, 5*time.Minute, &out); err != nil {
		return 0, err
	}
	return int(out.Accepted), nil
}

// l67PassiveOpens is the TCP connections a kernel has accepted, from the Tcp:
// lines of /proc/net/snmp (a header, then the values).
func l67PassiveOpens(snmp string) (int, error) {
	var header []string
	for _, ln := range strings.Split(snmp, "\n") {
		f := strings.Fields(ln)
		if len(f) < 2 || f[0] != "Tcp:" {
			continue
		}
		if header == nil {
			header = f
			continue
		}
		for i, h := range header {
			if h == "PassiveOpens" && i < len(f) {
				return strconv.Atoi(f[i])
			}
		}
	}
	return 0, errors.New("no PassiveOpens in /proc/net/snmp")
}

// rawUnauth is an unauthenticated bind (a name and an empty password) as a raw
// go-ldap client sends it, and what a WhoAmI says afterwards.
func (x *l67X) rawUnauth(dn string) (bindErr error, who string, whoErr error) {
	cfg, err := x.dir.d.pki.clientTLS(x.dir.uri)
	if err != nil {
		return err, "", nil
	}
	c, err := ldap.DialURL(x.dir.uri, ldap.DialWithTLSConfig(cfg))
	if err != nil {
		return err, "", nil
	}
	defer c.Close()
	if bindErr = c.UnauthenticatedBind(dn); bindErr != nil {
		return bindErr, "", nil
	}
	r, err := c.WhoAmI(nil)
	if err != nil {
		return nil, "", err
	}
	return nil, r.AuthzID, nil
}

// markerTime is when the directory's container logged that its fixture was
// loaded (docker's timestamp of that line).
func (x *l67X) markerTime() (time.Time, bool) {
	b, err := x.dir.d.dockerCompose("logs", "--no-color", "-t", x.dir.service).CombinedOutput()
	if err != nil {
		return time.Time{}, false
	}
	for _, ln := range strings.Split(string(b), "\n") {
		if !strings.Contains(ln, "fixture loaded") {
			continue
		}
		for _, f := range strings.Fields(ln) {
			if ts, err := time.Parse(time.RFC3339Nano, f); err == nil {
				return ts, true
			}
		}
	}
	return time.Time{}, false
}

// ---------------------------------------------------------------------------
// The cells.
// ---------------------------------------------------------------------------

func (x *l67X) cellA(t *testing.T) {
	for _, via := range []struct {
		name string
		dir  *labDir
	}{{"LDAPS", x.dir}, {"StartTLS", x.dir.viaStartTLS()}} {
		e := x.entry(t, via.dir, "alice") // the control: the broker's own bind works on the same server
		x.row("a. control", "the broker's bind found alice on %s over %s", e.Server.Label(), via.name)
		r := x.resolver(t, via.dir)
		err := x.check(t, r, e, "a: right password over "+via.name, x.pw)
		x.row("a. right password, "+via.name, "%s", l67Classify(err).show())
		if err != nil {
			x.fail("a: the right password over %s was %v", via.name, err)
		}
		err = x.check(t, r, e, "a: wrong password over "+via.name, x.wrong())
		res := l67Classify(err)
		x.row("a. wrong password, "+via.name, "%s", res.show())
		if res.Kind != "refused" {
			x.fail("a: a wrong password over %s was %s, want a PasswordRefusal", via.name, res.show())
		}
		// A right bind clears the wrong one from the directory's count.
		_ = x.check(t, r, e, "a: right password again, clearing the count", x.pw)
	}
}

func (x *l67X) cellB(t *testing.T) {
	e := x.entry(t, x.dir, "alice")
	r := x.resolver(t, x.dir)
	bindErr, who, whoErr := x.rawUnauth(e.DN)
	l67Record(x.ev, "b: raw UnauthenticatedBind(alice's DN)", bindErr)
	switch {
	case bindErr != nil:
		x.row("b. raw unauthenticated bind", "refused: %s", l67Classify(bindErr).show())
	case whoErr != nil:
		x.row("b. raw unauthenticated bind", "succeeded; WhoAmI: %s", errOrOK(whoErr))
	default:
		x.row("b. raw unauthenticated bind", "SUCCEEDED, as RFC 4513 §5.1.2 warns; WhoAmI authzId %q (empty is anonymous)", who)
	}
	// The control: the connection count sees a connection, here a real bind's.
	n0, err := x.conns(t)
	if err != nil {
		t.Fatalf("INVALID: %s: the connection count is unreadable: %v", x.dir.name, err)
	}
	n1, _ := x.conns(t)
	base := n1 - n0
	if err := x.check(t, r, e, "b: control, a real bind", x.pw); err != nil {
		t.Fatalf("INVALID: the control bind: %v", err)
	}
	n2, _ := x.conns(t)
	if l67Unchanged(n1, n2, base) {
		t.Fatalf("INVALID: %s: the connection count did not move for a real bind (%d, %d, reading costs %d), so it cannot show that an empty password opens none", x.dir.name, n1, n2, base)
	}
	x.row("b. control", "a real bind moved the connection count %d -> %d (reading it costs %d)", n1, n2, base)
	err = x.check(t, r, e, "b: CheckPassword with an empty password", "")
	n3, _ := x.conns(t)
	x.ev.add(evidenceLine{Event: "l67_connections", Label: "b: after the empty password", Count: &n3})
	x.row("b. CheckPassword(..., \"\")", "%s; connections %d -> %d", l67Classify(err).show(), n2, n3)
	if !errors.Is(err, directory.ErrEmptyPassword) {
		x.fail("b: an empty password was %v, want ErrEmptyPassword", err)
	}
	if !l67Unchanged(n2, n3, base) {
		x.fail("b: the connection count moved %d -> %d for an empty password (reading costs %d)", n2, n3, base)
	}
}

// lock puts user over the lockout threshold with wrong passwords, as a person's
// typos would.
func (x *l67X) lock(t *testing.T, r *directory.Resolver, e directory.SignInEntry, user string) {
	t.Helper()
	for i := 0; i < l67Threshold+2; i++ {
		_ = x.check(t, r, e, fmt.Sprintf("c: wrong password %d to lock %s", i+1, user), x.wrong())
		if i+1 >= l67Threshold {
			if st, err := x.state(t, user); err == nil && st.Locked {
				return
			}
		}
	}
}

func (x *l67X) cellC(t *testing.T) {
	for _, u := range []struct {
		user, state string
		got         func(l67State) bool
	}{
		{"l67-expired", "expired", func(s l67State) bool { return s.Expired }},
		{"l67-mustchange", "must change", func(s l67State) bool { return s.MustChange }},
		{"l67-disabled", "disabled", func(s l67State) bool { return s.Disabled }},
		{"l67-locked", "locked", func(s l67State) bool { return s.Locked }},
	} {
		e := x.entry(t, x.dir, u.user)
		r := x.resolver(t, x.dir)
		if u.user == "l67-locked" {
			x.lock(t, r, e, u.user)
		}
		st, stErr := x.state(t, u.user)
		switch {
		case stErr != nil:
			x.limit("c: %s's state could not be read from the directory: %v", u.user, stErr)
			x.row("c. control, "+u.state, "the directory's own view is unreadable: %v", stErr)
		case !u.got(st):
			x.limit("c: the directory does not hold %s as %s (%s); its answers below are those of an account in no such state", u.user, u.state, st)
			x.row("c. control, "+u.state, "NOT in the state meant: %s", st)
		default:
			x.row("c. control, "+u.state, "the directory reports it: %s", st)
		}
		held := stErr == nil && u.got(st)
		for _, p := range []struct{ name, pw string }{{"right", x.pw}, {"wrong", x.wrong()}} {
			err := x.check(t, r, e, fmt.Sprintf("c: %s, %s password", u.user, p.name), p.pw)
			res := l67Classify(err)
			x.row(fmt.Sprintf("c. %s, %s password", u.state, p.name), "%s", res.show())
			if held && p.name == "right" && err == nil {
				// A right password bound a person the directory itself holds in a
				// state a bind should refuse.
				x.fail("c: %s's right password bound, though the directory holds the account as %s", u.user, u.state)
			}
		}
	}
	// Alice, the positive control for the right password.
	e := x.entry(t, x.dir, "alice")
	err := x.check(t, x.resolver(t, x.dir), e, "c: control, alice's right password", x.pw)
	x.row("c. control", "alice's right password: %s", l67Classify(err).show())
	if err != nil {
		t.Fatalf("INVALID: alice's right password was refused: %v", err)
	}
}

// ---- cell (f)

func (x *l67X) cellF(t *testing.T) {
	e := x.entry(t, x.dir, "alice")
	if e.CreatedAt.IsZero() {
		x.fail("f: SignInEntry(alice).CreatedAt is zero")
		x.row("f. CreatedAt", "zero")
		return
	}
	// The control: the directory's own attribute is the same instant.
	if st, err := x.state(t, "alice"); err == nil && !st.Created.IsZero() {
		diff := e.CreatedAt.Sub(st.Created)
		x.row("f. control", "the directory's own creation time of alice is %s; SignInEntry read %s", st.Created.UTC().Format(time.RFC3339), e.CreatedAt.UTC().Format(time.RFC3339))
		if diff < -time.Second || diff > time.Second {
			x.fail("f: SignInEntry read %s, the directory says %s", e.CreatedAt, st.Created)
		}
	}
	seed := x.seedAt
	if m, ok := x.markerTime(); ok {
		seed = m
	}
	if seed.IsZero() {
		x.fail("f: the seed's time is unknown")
		return
	}
	d := seed.Sub(e.CreatedAt)
	x.row("f. CreatedAt", "%s, %s before the fixture was logged loaded", e.CreatedAt.UTC().Format(time.RFC3339), d.Round(time.Second))
	if d < -time.Minute || d > time.Minute {
		x.fail("f: CreatedAt %s is %s from the seed (%s), want within a minute", e.CreatedAt, d, seed)
	}
}

// ---------------------------------------------------------------------------
// Persons: the second factor the harness plays.
// ---------------------------------------------------------------------------

// l67Person is one person's authenticator: the secret, and the last step the
// broker was given. The secret is never printed.
type l67Person struct {
	name   string
	secret []byte
	last   int64
}

// code is the code of the next step the broker will take, after waiting for
// the clock to reach it.
func (p *l67Person) code() string {
	step, wait := l67NextStep(p.last, time.Now())
	time.Sleep(wait)
	c, err := l67CodeAt(p.secret, step)
	if err != nil {
		panic(err)
	}
	p.last = step
	return c
}

// enroll takes name through the enrollment: the first sign-in with no code
// answers 202 with the secret, the first code confirms it.
func (x *l67X) enroll(t *testing.T, a *l67API, name string) *l67Person {
	t.Helper()
	ans := a.signIn(name, x.pw, "")
	if ans.Status != http.StatusAccepted || ans.Enroll == nil {
		t.Fatalf("INVALID: enrolling %s: %d %s (%s)", name, ans.Status, ans.Error, ans.Detail)
	}
	secret, err := l67SecretOf(ans.Enroll.URI)
	if err != nil {
		t.Fatalf("INVALID: enrolling %s: %v", name, err)
	}
	p := &l67Person{name: name, secret: secret}
	conf := a.confirm(ans.Enroll.Handle, p.code())
	if conf.Status != http.StatusOK || !conf.Cert {
		t.Fatalf("INVALID: confirming %s's enrollment: %d %s (%s)", name, conf.Status, conf.Error, conf.Detail)
	}
	return p
}

// l67SecretOf is the key in an otpauth URI.
func l67SecretOf(uri string) ([]byte, error) {
	u, err := url.Parse(uri)
	if err != nil || u.Scheme != "otpauth" {
		return nil, errors.New("the enrollment's URI is not an otpauth one")
	}
	return totp.DecodeSecret(strings.ToUpper(u.Query().Get("secret")))
}

// ---- cells (d) and (e)

// startBroker brings up the cells' broker on the memory store, creating its
// enrollments, and enrolls carol and dave.
func (x *l67X) startBroker(t *testing.T, opts l67BrokerOpts) {
	t.Helper()
	if x.broker != nil {
		return
	}
	x.broker = newL67Broker(t, x.owner, x.dir, opts)
	if out, code := x.broker.port49(t, "directory", "init-enrollments", "--socket", x.broker.admin); code != 0 {
		t.Fatalf("INVALID: init-enrollments: exit %d: %s", code, oneLineMax(out, 300))
	}
	a := x.broker.api(t)
	x.people = map[string]*l67Person{}
	for _, n := range []string{"carol", "dave"} {
		x.people[n] = x.enroll(t, a, n)
		x.broker.unlock(t, n)
	}
}

// wrongSignIn is one sign-in for name with a wrong password and the right code
// (a throttled one is refused before the code is read, so it takes no step). It
// returns the answer, when the request was sent and when the answer came.
func (x *l67X) wrongSignIn(t *testing.T, a *l67API, name string, takesStep bool) (ans l67Answer, sent, back time.Time) {
	t.Helper()
	code := "000000"
	if takesStep {
		code = x.people[name].code()
	}
	sent = time.Now()
	ans = a.signIn(name, x.wrong(), code)
	back = time.Now()
	x.ev.add(evidenceLine{Event: "l67_signin", Label: "wrong password, right code for " + name,
		ResultCode: &ans.Status, Data: ans.Error})
	return ans, sent, back
}

func (x *l67X) cellD(t *testing.T) {
	x.startBroker(t, l67BrokerOpts{})
	a := x.broker.api(t)
	// ---- six wrong passwords at port49's defaults
	e := x.entry(t, x.dir, "carol")
	r := x.resolver(t, x.dir)
	if err := x.check(t, r, e, "d: control, carol's right password", x.pw); err != nil {
		t.Fatalf("INVALID: carol's right password: %v", err)
	}
	st, err := x.state(t, "carol")
	if err != nil || st.Count != 0 || st.Locked {
		t.Fatalf("INVALID: carol starts with the directory's %s (%v)", st, err)
	}
	x.row("d. control", "carol's failed count before: %d, not locked", st.Count)
	var codes []string
	for i := 1; i <= l67Defaults+1; i++ {
		ans, _, _ := x.wrongSignIn(t, a, "carol", i <= l67Defaults)
		cs, _ := x.state(t, "carol")
		codes = append(codes, fmt.Sprintf("%d: %d %s, directory count %d", i, ans.Status, ans.Error, cs.Count))
		c := cs.Count
		x.ev.add(evidenceLine{Event: "l67_count", Label: fmt.Sprintf("d: carol's count after wrong sign-in %d", i), Count: &c})
		want, wantErr := http.StatusUnauthorized, "sign_in_refused"
		if i > l67Defaults {
			want, wantErr = http.StatusTooManyRequests, "sign_in_throttled"
		}
		if ans.Status != want || ans.Error != wantErr {
			x.fail("d: wrong sign-in %d was %d %s, want %d %s", i, ans.Status, ans.Error, want, wantErr)
		}
		if i == l67Defaults && cs.Count != l67Defaults {
			x.fail("d: the directory's count after %d wrong sign-ins is %d, want %d", i, cs.Count, l67Defaults)
		}
		if i > l67Defaults && cs.Count != l67Defaults {
			x.fail("d: the sixth sign-in, throttled, moved the directory's count to %d, want it left at %d (no bind)", cs.Count, l67Defaults)
		}
	}
	x.row("d. six wrong passwords, defaults", "%s", strings.Join(codes, "; "))
	st, _ = x.state(t, "carol")
	x.row("d. control, not locked", "after six: %s", st)
	if st.Locked {
		x.fail("d: carol is locked after %d wrong passwords", l67Defaults)
	}
	if err := x.check(t, r, e, "d: control, a right password after the five", x.pw); err != nil {
		x.fail("d: carol's right password after the window's five was %v", err)
	}
	x.broker.unlock(t, "carol")

	// ---- nine across a window boundary, against the lockout threshold
	x.broker.restart(t, l67BrokerOpts{Window: l67Window})
	a = x.broker.api(t)
	de := x.entry(t, x.dir, "dave")
	if err := x.check(t, r, de, "d: control, dave's right password", x.pw); err != nil {
		t.Fatalf("INVALID: dave's right password: %v", err)
	}
	// The broker's window runs from the first attempt it counts: sent at or after
	// firstSent, answered by firstBack. The four before the boundary are sent within
	// the window of firstSent; the five after, after firstBack plus the window.
	var firstSent, firstBack time.Time
	var seq []string
	send := func(i int) {
		ans, sent, back := x.wrongSignIn(t, a, "dave", true)
		if i == 1 {
			firstSent, firstBack = sent, back
		}
		if i <= l67Before && sent.Sub(firstSent) >= l67Window-2*time.Second {
			x.fail("d: straddle sign-in %d was sent %s after the first, too near the window's %s end to be before it", i, sent.Sub(firstSent).Round(time.Second), l67Window)
		}
		ds, _ := x.state(t, "dave")
		seq = append(seq, fmt.Sprintf("%d: %d, count %d", i, ans.Status, ds.Count))
		c := ds.Count
		x.ev.add(evidenceLine{Event: "l67_count", Label: fmt.Sprintf("d: dave's count after wrong sign-in %d of the straddle", i), Count: &c})
		if ans.Status != http.StatusUnauthorized {
			x.fail("d: straddle sign-in %d was %d %s, want a refusal that reached the directory", i, ans.Status, ans.Error)
		}
	}
	for i := 1; i <= l67Before; i++ {
		send(i)
	}
	// The window runs from the first attempt; wait for it to end.
	if wait := time.Until(firstBack.Add(l67Window + 3*time.Second)); wait > 0 {
		time.Sleep(wait)
	}
	for i := l67Before + 1; i <= l67Before+l67After; i++ {
		send(i)
	}
	ds, _ := x.state(t, "dave")
	x.row("d. nine across a boundary ("+l67Window.String()+" window)", "%s", strings.Join(seq, "; "))
	x.row("d. after nine", "%s; the directory's threshold is %d, a margin of %d", ds, l67Threshold, l67Threshold-ds.Count)
	if ds.Count != l67Before+l67After {
		x.fail("d: the directory's count after nine is %d, want %d", ds.Count, l67Before+l67After)
	}
	if ds.Locked {
		x.fail("d: the account locked after %d wrong passwords across a boundary, under a threshold of %d", l67Before+l67After, l67Threshold)
	}
	// The control for "not locked": the lockout is armed. The tenth locks.
	_ = x.check(t, r, de, "d: control, the tenth wrong password", x.wrong())
	ds, _ = x.state(t, "dave")
	x.row("d. control, the tenth", "%s", ds)
	if !ds.Locked {
		x.fail("d: the tenth wrong password did not lock dave (%s), so \"not locked after nine\" shows nothing", ds)
	}
}

func (x *l67X) cellE(t *testing.T) {
	x.startBroker(t, l67BrokerOpts{Window: l67Window})
	a := x.broker.api(t)
	p := x.people["carol"]
	x.broker.unlock(t, "carol")
	// The control: the right password and the right code sign in.
	ans := a.signIn("carol", x.pw, p.code())
	x.row("e. control", "right password, right code: %d %s", ans.Status, ans.Error)
	if ans.Status != http.StatusOK || !ans.Cert {
		t.Fatalf("INVALID: carol's right sign-in: %d %s (%s)", ans.Status, ans.Error, ans.Detail)
	}
	before, err := x.state(t, "carol")
	if err != nil {
		t.Fatalf("INVALID: carol's state: %v", err)
	}
	bad, err := l67WrongCode(p.secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	ans = a.signIn("carol", x.pw, bad)
	after, _ := x.state(t, "carol")
	b, c := before.Count, after.Count
	x.ev.add(evidenceLine{Event: "l67_signin", Label: "e: right password, wrong code", ResultCode: &ans.Status, Data: ans.Error})
	x.ev.add(evidenceLine{Event: "l67_count", Label: "e: count before", Count: &b})
	x.ev.add(evidenceLine{Event: "l67_count", Label: "e: count after", Count: &c})
	x.row("e. a wrong code", "%d %s; the directory's failed count %d -> %d", ans.Status, ans.Error, before.Count, after.Count)
	if ans.Status != http.StatusUnauthorized || ans.Error != "sign_in_refused" {
		x.fail("e: a wrong code was %d %s, want 401 sign_in_refused", ans.Status, ans.Error)
	}
	if before.Count != after.Count {
		x.fail("e: the directory's count moved %d -> %d for a wrong code", before.Count, after.Count)
	}
}

// ---- cell (g)

func (x *l67X) cellG(t *testing.T) {
	gate := newTCPGate(t, l67HostPort(x.dir.uri))
	b := newL67Broker(t, t, x.dir, l67BrokerOpts{DirURI: "ldaps://localhost:" + gate.port()})
	a := b.api(t)
	// The control: before init-enrollments the store is missing, and nothing
	// is created by trying.
	ans := a.signIn("alice", x.pw, "")
	_, statErr := os.Stat(filepath.Join(b.dir, "enrollments.json"))
	x.row("g. memory, control", "a sign-in before init-enrollments: %d %s; enrollments.json exists: %v", ans.Status, ans.Error, statErr == nil)
	if ans.Status != http.StatusServiceUnavailable || ans.Error != "enrollment_store_lost" || statErr == nil {
		t.Fatalf("INVALID: before init-enrollments: %d %s, enrollments.json exists %v", ans.Status, ans.Error, statErr == nil)
	}
	if out, code := b.port49(t, "directory", "init-enrollments", "--socket", b.admin); code != 0 {
		t.Fatalf("INVALID: init-enrollments: exit %d: %s", code, oneLineMax(out, 300))
	}
	if _, err := os.Stat(filepath.Join(b.dir, "enrollments.json")); err != nil {
		x.fail("g (memory): init-enrollments left no enrollments.json: %v", err)
	}
	cli := newL67CLI(t, "https://"+b.addr, filepath.Join(b.pki, testpki.LabCA))
	x.endToEnd(t, "memory", cli, l67Device, func() { gate.stop() }, func(string) { b.leakCheck(t, x) })
}

// endToEnd is cell (g)'s common run, for either broker: login --directory
// enrols alice, token mints, the directory stops, token mints from grace, and
// login --directory --sign-in exits 1 saying the directory did not answer.
func (x *l67X) endToEnd(t *testing.T, which string, cli *l67CLI, device string, stopDirectory func(), leak func(string)) {
	t.Helper()
	label := "g. " + which
	login := cli.login(t, l67LoginIn{name: "alice", password: x.pw, enroll: true})
	l67Exit(x.ev, label+": login --directory, enrolling", login.Exit, login.Said)
	x.row(label+", login --directory", "exit %d; enrolled %v; %s", login.Exit, login.Enrolled, login.Said)
	if login.Exit != 0 || !login.Enrolled {
		t.Fatalf("INVALID: %s: login --directory exit %d: %s", which, login.Exit, login.Said)
	}
	person := &l67Person{name: "alice", secret: login.Secret, last: login.Step}
	tok := cli.token(t, device)
	l67Exit(x.ev, label+": token", tok.Exit, tok.Said)
	x.row(label+", token "+device, "exit %d; minted %v", tok.Exit, tok.Minted)
	if tok.Exit != 0 || !tok.Minted {
		x.fail("g (%s): token %s exited %d: %s", which, device, tok.Exit, tok.Said)
	}
	stopDirectory()
	grace := cli.token(t, device)
	l67Exit(x.ev, label+": token, directory stopped", grace.Exit, grace.Said)
	x.row(label+", token with the directory stopped", "exit %d; minted %v", grace.Exit, grace.Minted)
	if grace.Exit != 0 || !grace.Minted {
		x.fail("g (%s): token with the directory stopped exited %d: %s", which, grace.Exit, grace.Said)
	}
	cli.agent.stopAgent() // login will not sign in again over a running agent that holds the session
	again := cli.login(t, l67LoginIn{name: "alice", password: x.pw, code: person.code, extra: []string{"--sign-in"}})
	l67Exit(x.ev, label+": login --directory --sign-in, directory stopped", again.Exit, again.Said)
	x.row(label+", login --directory --sign-in with the directory stopped", "exit %d; %s", again.Exit, again.Said)
	if again.Exit != 1 || !strings.Contains(again.Said, "the directory did not answer") {
		x.fail("g (%s): login --sign-in with the directory stopped exited %d: %s; want exit 1 saying the directory did not answer", which, again.Exit, again.Said)
	}
	if leak != nil {
		leak(which)
	}
}

// l67Exit writes a CLI run's outcome to the evidence.
func l67Exit(ev *evidenceLog, label string, exit int, said string) {
	ev.add(evidenceLine{Event: "l67_cli", Label: label, ResultCode: &exit, Error: said})
}

// ---------------------------------------------------------------------------
// The compose half of (g): the stack's broker on etcd, with OpenLDAP.
// ---------------------------------------------------------------------------

// l67ComposePrepare is e2ePrepare, with the people's password in OpenLDAP's
// environment.
func l67ComposePrepare(pw string) func(*composeStack) error {
	return func(c *composeStack) error {
		if err := e2ePrepare(c); err != nil {
			return err
		}
		f, err := os.OpenFile(filepath.Join(c.local, "openldap.env"), os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			return err
		}
		defer f.Close()
		_, err = fmt.Fprintf(f, "LAB_L67=1\nLAB_L67_PASSWORD=%s\n", pw)
		return err
	}
}

// l67Files is e2eFiles with the directory_password verifier and issuance on the
// compose broker, as the only human verifier: no client_ca_file and no
// certificate_status, the shape the plan ships (decision 47).
func l67Files(files map[string]string) error {
	if err := e2eFiles(files); err != nil {
		return err
	}
	b := files["port49-broker.yaml"]
	for _, line := range []string{"  client_ca_file: " + e2eDirDir + "/users-ca.pem\n", "  certificate_status: {disabled: true}\n"} {
		if !strings.Contains(b, line) {
			return fmt.Errorf("port49-broker.yaml has no line %q to remove", strings.TrimSpace(line))
		}
		b = strings.Replace(b, line, "", 1)
	}
	const state = "  state_dir: /var/lib/port49-broker\n"
	if !strings.Contains(b, state) {
		return errors.New("port49-broker.yaml has no state_dir to put the identity block before")
	}
	files["port49-broker.yaml"] = strings.Replace(b, state, "  identity:\n    humans:\n      - type: directory_password\n"+
		"        principal_domains: [corp.example.com]\n        second_factor: totp\n    issuance: {}\n"+state, 1)
	return nil
}

func (x *l67X) composeHalf(t *testing.T) {
	sel, _, err := platformSelection()
	if err != nil {
		t.Fatal(err)
	}
	var l *lab
	for _, p := range sel {
		if e2ePlatform(p.name) {
			l = labFor(t, p)
			break
		}
	}
	if l == nil {
		t.Skip("PORT49_LAB_PLATFORMS selects neither arista_eos nor juniper_vjunos-router, so the compose stack's broker is not brought up")
	}
	c := l.startComposeWith(t, composeOptions{Overlay: "directory.yaml", Files: l67Files, Prepare: l67ComposePrepare(x.pw), Phase: "l67"})
	brokerCA := filepath.Join(root, slicePKIDir, testpki.LabCA)
	a, err := newL67API(sliceBrokerURL, brokerCA)
	if err != nil {
		t.Fatal(err)
	}
	// No issuing CA yet: the broker names what to run, as in L56.
	if out, err := c.run("run", "--rm", "--no-deps", "port49-broker", "init-issuer"); err != nil || !strings.Contains(out, "created the issuing CA") {
		t.Fatalf("INVALID: port49-broker init-issuer: %v: %s", err, oneLineMax(out, 300))
	}
	if _, err := c.run("restart", "port49-broker"); err != nil {
		t.Fatalf("INVALID: restarting the broker: %v", err)
	}
	deadline := time.Now().Add(3 * time.Minute)
	var ans l67Answer
	for {
		ans = a.signIn("alice", x.pw, "")
		if ans.Status != 0 && ans.Status != http.StatusNotFound {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("INVALID: the compose broker never answered a sign-in: %d %s", ans.Status, ans.Error)
		}
		time.Sleep(2 * time.Second)
	}
	x.row("g. etcd, control", "a sign-in before init-enrollments: %d %s", ans.Status, ans.Error)
	if ans.Status != http.StatusServiceUnavailable || ans.Error != "enrollment_store_lost" {
		t.Fatalf("INVALID: before init-enrollments: %d %s, want 503 enrollment_store_lost", ans.Status, ans.Error)
	}
	if out, err := c.run("exec", "-T", "port49-broker", "port49", "directory", "init-enrollments", "--socket",
		"/run/port49/port49-broker.sock"); err != nil {
		t.Fatalf("INVALID: init-enrollments: %v: %s", err, oneLineMax(out, 300))
	}
	cli := newL67CLI(t, sliceBrokerURL, brokerCA)
	x.endToEnd(t, "etcd", cli, l.p.node, func() {
		if out, err := c.run("stop", "openldap"); err != nil {
			t.Fatalf("INVALID: stopping openldap: %v: %s", err, oneLineMax(out, 300))
		}
	}, func(string) {
		logs, err := c.run("logs", "port49-broker")
		if err != nil {
			x.fail("g (etcd): the broker's log could not be read: %v", err)
			return
		}
		if strings.Contains(logs, x.pw) {
			x.fail("g (etcd): the broker's log holds the person's password")
		}
	})
}

// ---------------------------------------------------------------------------
// The run of one directory.
// ---------------------------------------------------------------------------

// l67Directory runs the cells on dir and writes its note and evidence.
func l67Directory(t *testing.T, d *directories, dir *labDir, pw string, seedAt time.Time) {
	t.Helper()
	ev := evidence(t, d, "L67-"+dir.name)
	ev.hide(pw)
	x := &l67X{t: t, owner: t, d: d, dir: dir, pw: pw, ev: ev, seedAt: seedAt}
	defer func() {
		note := x.note()
		ev.assertClean(t, append([]string{pw, d.password}, d.extra...)...)
		writeResult(t, d, "L67", dir, l67Claim, dir.version(t), note, "tests/lab/evidence/L67-"+dir.name+".json")
		if len(x.failed) > 0 {
			t.Errorf("L67 on %s: %s", dir.name, strings.Join(x.failed, "; "))
		}
	}()
	for _, c := range l67Cells {
		c := c
		if !t.Run(c.ID+"_"+c.Name, func(t *testing.T) {
			x.t = t
			switch c.ID {
			case "a":
				x.cellA(t)
			case "b":
				x.cellB(t)
			case "c":
				x.cellC(t)
			case "d":
				x.cellD(t)
			case "e":
				x.cellE(t)
			case "f":
				x.cellF(t)
			case "g":
				t.Run("memory", func(t *testing.T) { x.cellG(t) })
				if dir.name == platOpenLDAP {
					t.Run("etcd", func(t *testing.T) { x.composeHalf(t) })
				}
			}
		}) {
			x.fail("cell %s (%s) did not finish; the test log says why", c.ID, c.Name)
		}
	}
}

// note is the observation of the note: the table, then what could not be
// measured and what was not as the claim says.
func (x *l67X) note() string {
	var b strings.Builder
	b.WriteString(x.dir.configNote())
	b.WriteString("The people's password is generated for each run (24 characters from `crypto/rand`) and held in memory; the evidence " +
		"writes `<alice's password>` wherever it would have been. Every cell's first row is its positive control. \"Failed count\" " +
		"is the directory's own: `pwdFailureTime` values on OpenLDAP, `badPwdCount` on Samba and the DC. The lockout threshold is " +
		fmt.Sprint(l67Threshold) + " on all three (OpenLDAP: `pwdMaxFailure 10`, `pwdFailureCountInterval 600`, `pwdLockout TRUE`, " +
		"`olcPPolicyUseLockout TRUE`; AD: threshold 10, observation window and duration 10 minutes).\n\n")
	b.WriteString("| cell | observed |\n|---|---|\n")
	b.WriteString(strings.Join(x.rows, "\n"))
	b.WriteString("\n")
	if len(x.limits) > 0 {
		b.WriteString("\n**Not measurable here:**\n\n- " + strings.Join(x.limits, "\n- ") + "\n")
	}
	if len(x.failed) > 0 {
		b.WriteString("\n**Not as the claim says:**\n\n- " + strings.Join(x.failed, "\n- ") + "\n")
	}
	return b.String()
}

// l67Prepare is what the containers need before they start: the people's
// password, and L67's note shape.
func l67Prepare(pw string) func(*directories) {
	return func(d *directories) {
		d.runSel = "^TestL67$"
		d.extra = append(d.extra, pw)
		l67Describe(d)
		f, err := os.OpenFile(filepath.Join(d.dir, "lab.env"), os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			panic(err)
		}
		defer f.Close()
		if _, err := fmt.Fprintf(f, "LAB_L67=1\nLAB_L67_PASSWORD=%s\n", pw); err != nil {
			panic(err)
		}
	}
}

func l67Describe(d *directories) {
	d.capture = "one JSON line per check, sign-in, count and CLI run: the check's kind (`l67_ok`, `l67_refused`, `l67_ldap`, ...), the LDAP " +
		"result code, the diagnostic data (AD's code, or ppolicy's error), and the directory's failed-password or connection count. " +
		"There are no search lines, and the wire is LDAPS, so a pcap would be encrypted."
	d.credentials = "none appear here or in the evidence. The people's password is generated for each run from `crypto/rand`, held in " +
		"memory and written to the evidence as `<alice's password>`; no TOTP secret or code, token or key is printed or kept."
}

func TestL67(t *testing.T) {
	pw, err := l67Password()
	if err != nil {
		t.Fatal(err)
	}
	d := startDirectoriesWith(t, l67Prepare(pw))
	seedAt := time.Now()
	t.Run("directories", func(t *testing.T) {
		for _, dir := range d.all() {
			dir := dir
			t.Run(dir.name, func(t *testing.T) {
				t.Parallel()
				l67Directory(t, d, dir, pw, seedAt)
			})
		}
	})
}

func TestL67Windows(t *testing.T) {
	if os.Getenv("PORT49_LAB_L67_WINDOWS") != "1" {
		t.Skip("starts the Windows DC; set PORT49_LAB_L67_WINDOWS=1 to run it")
	}
	pw, err := l67Password()
	if err != nil {
		t.Fatal(err)
	}
	d := newDirectories(t)
	d.runSel = "^TestL67Windows$"
	d.extra = append(d.extra, pw)
	l67Describe(d)
	dc := startWindowsDC(t, d)
	var seed struct {
		ExpiredSet bool   `json:"expired_set"`
		ExpiredWhy string `json:"expired_why"`
	}
	dc.win.run(t, "l67", map[string]any{"step": "seed", "person_password": pw}, 30*time.Minute, &seed)
	var created struct {
		WhenCreated string `json:"when_created"`
	}
	dc.win.run(t, "l67", map[string]any{"step": "state", "name": "alice"}, 5*time.Minute, &created)
	seedAt, _ := time.Parse(time.RFC3339Nano, created.WhenCreated)
	if !seed.ExpiredSet {
		t.Logf("the DC would not hold l67-expired as expired: %s", oneLineMax(seed.ExpiredWhy, 300))
	}
	l67Directory(t, d, dc, pw, seedAt)
}

// ---------------------------------------------------------------------------
// The broker: port49d on the memory store, over a directory.
// ---------------------------------------------------------------------------

const l67Device = "leaf1"

// l67BrokerOpts is what a cell changes about the broker's configuration.
type l67BrokerOpts struct {
	Window time.Duration // rate_limits.window; 0 is port49's default
	DirURI string        // the directory's URI as the broker reaches it; "" is the directory's own
}

// l67HostPort is host:port of a directory URI, with a Windows DC's name as the
// published ports are reached: localhost. The subprocess does not share this
// process's resolver (windows_resolve_test.go).
func l67HostPort(uri string) string {
	u, err := url.Parse(strings.Replace(uri, winDCHost, "localhost", 1))
	if err != nil {
		return ""
	}
	return u.Host
}

// l67BrokerFiles are port49d.yaml, policy.yaml and inventory.yaml for a broker
// in dir with the TLS files of pki, a directory_password verifier over x, and
// admin_socket, by name.
func l67BrokerFiles(dir, pki string, x *labDir, o l67BrokerOpts) map[string]string {
	uri := o.DirURI
	if uri == "" {
		uri = "ldaps://" + l67HostPort(x.uri)
	}
	limits := ""
	if o.Window > 0 {
		limits = fmt.Sprintf("        rate_limits: {window: %s}\n", o.Window)
	}
	cfg := fmt.Sprintf(`listen: "127.0.0.1:0"
metrics_listen: "127.0.0.1:0"
admin_socket: %[1]s
inventory_file: %[2]s
keys:
  lab_key:
    current: {version: 1, secret_env: PORT49_LAB_KEY}
encryption:
  current: {id: lab1, secret_env: PORT49_LAB_ENC_KEY}
accounting: {spool_path: %[3]s}
broker:
  listen: "127.0.0.1:0"
  tls_cert_file: %[4]s
  tls_key_file: %[5]s
  identity:
    humans:
      - type: directory_password
        principal_domains: [corp.example.com]
        second_factor: totp
%[6]s    issuance: {}
  policy_file: %[7]s
  revocations_file: %[8]s
  policy_watch_interval: 1s
  refresh_interval: 5m
  directory:
    servers:
      - {uri: "%[9]s", priority: 100, site: lab}
    site: lab
    ca_file: %[10]s
    bind:
      mechanism: simple
      bind_dn: "%[11]s"
      password_env: LAB_DIRECTORY_BIND_PASSWORD
    base_dn: "%[12]s"
    groups_base_dn: "%[13]s"
    user_filter: "%[14]s"
    group_filter: "%[15]s"
    principal_attribute: mail
    username_attribute: %[16]s
    nested_groups: direct
    grace: 4h
`, filepath.Join(dir, "admin.sock"), filepath.Join(dir, "inventory.yaml"), filepath.Join(dir, "acct.jsonl"),
		filepath.Join(pki, testpki.LabServerCert), filepath.Join(pki, testpki.LabServerKey), limits,
		filepath.Join(dir, "policy.yaml"), filepath.Join(dir, "revocations.json"), uri, x.d.pki.caFile, x.bindDN, x.baseDN,
		x.groupsBaseDN, x.userFilter, x.groupFilter, x.usernameAttr)
	policy := `scopes:
  - {name: all_devices, match: {}}
roles:
  - {name: network_admin, privilege: admin, permit: ["**"]}
subjects:
  - {name: alice, identity: ["user:alice@corp.example.com"], token_ttl: 900s}
grants:
  - {subject: alice, scope: all_devices, roles: [network_admin], max_privilege: admin}
key_groups:
  - {match: {cidr: 127.0.0.0/8}, key_ref: lab_key}
`
	inventory := fmt.Sprintf("devices:\n  - {name: %s, platform: arista_eos, addresses: [127.0.0.1]}\n", l67Device)
	return map[string]string{"port49d.yaml": cfg, "policy.yaml": policy, "inventory.yaml": inventory}
}

// l67Broker is bin/port49d running a broker over a directory.
type l67Broker struct {
	x                  *labDir
	dir, pki, cfg      string
	admin, addr, errTo string
	bin, cli           string
	cmd                *exec.Cmd
	done               chan struct{}
	opts               l67BrokerOpts
}

func l67Bins(t *testing.T) (port49d, port49 string) {
	t.Helper()
	repo, err := repoRoot() // the directory tests do not run initGlobal, so root may be unset
	if err != nil {
		t.Fatal(err)
	}
	for _, b := range []string{"port49d", "port49"} {
		if _, err := os.Stat(filepath.Join(repo, "bin", b)); err != nil {
			t.Fatalf("bin/%s is missing: run `make build` first", b)
		}
	}
	return filepath.Join(repo, "bin", "port49d"), filepath.Join(repo, "bin", "port49")
}

// newL67Broker writes the broker's files into a private directory, makes its
// revocations file and its issuing CA, and starts it.
// owner is the test whose end removes it: a broker several cells share belongs
// to the directory's test, not to the cell that happened to start it.
func newL67Broker(t, owner *testing.T, x *labDir, o l67BrokerOpts) *l67Broker {
	t.Helper()
	port49d, port49 := l67Bins(t)
	dir, err := os.MkdirTemp("", "p49l67")
	if err != nil {
		t.Fatal(err)
	}
	owner.Cleanup(func() { os.RemoveAll(dir) })
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	b := &l67Broker{x: x, dir: dir, pki: filepath.Join(dir, "pki"), cfg: filepath.Join(dir, "port49d.yaml"),
		admin: filepath.Join(dir, "admin.sock"), errTo: filepath.Join(dir, "port49d.err"), bin: port49d, cli: port49, opts: o}
	if err := testpki.WriteLab(b.pki, sliceEmail, time.Now()); err != nil {
		t.Fatal(err)
	}
	b.write(t, o)
	env := b.env()
	for _, args := range [][]string{{"init-revocations", "--config", b.cfg}, {"init-issuer", "--config", b.cfg}} {
		cmd := exec.Command(port49d, args...)
		cmd.Env = env
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("INVALID: port49d %s: %v: %s", args[0], err, oneLineMax(string(out), 400))
		}
	}
	b.start(t)
	owner.Cleanup(b.stop)
	return b
}

func (b *l67Broker) write(t *testing.T, o l67BrokerOpts) {
	t.Helper()
	for name, body := range l67BrokerFiles(b.dir, b.pki, b.x, o) {
		if err := os.WriteFile(filepath.Join(b.dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func (b *l67Broker) env() []string {
	return append(localBrokerEnv(""), "LAB_DIRECTORY_BIND_PASSWORD="+b.x.d.password)
}

func (b *l67Broker) said() string {
	raw, _ := os.ReadFile(b.errTo)
	return string(raw)
}

func (b *l67Broker) start(t *testing.T) {
	t.Helper()
	_ = os.Remove(b.admin)
	errf, err := os.Create(b.errTo)
	if err != nil {
		t.Fatal(err)
	}
	b.cmd = exec.Command(b.bin, "-config", b.cfg)
	b.cmd.Dir = b.dir
	b.cmd.Stderr = errf
	b.cmd.Env = b.env()
	if err := b.cmd.Start(); err != nil {
		errf.Close()
		t.Fatalf("start port49d: %v", err)
	}
	b.done = make(chan struct{})
	go func(cmd *exec.Cmd, done chan struct{}) { cmd.Wait(); errf.Close(); close(done) }(b.cmd, b.done)
	deadline := time.Now().Add(60 * time.Second)
	for {
		if m := brokerListening.FindStringSubmatch(b.said()); m != nil {
			b.addr = m[1]
			break
		}
		select {
		case <-b.done:
			t.Fatalf("port49d exited during startup; its stderr:\n%s", tailOf(b.said(), 2000))
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("port49d never said it was listening; its stderr:\n%s", tailOf(b.said(), 2000))
		}
		time.Sleep(200 * time.Millisecond)
	}
	for ; time.Now().Before(deadline); time.Sleep(200 * time.Millisecond) {
		if _, err := os.Stat(b.admin); err == nil {
			return
		}
	}
	t.Fatalf("port49d's admin socket never appeared; its stderr:\n%s", tailOf(b.said(), 2000))
}

func (b *l67Broker) stop() {
	if b.cmd == nil || b.cmd.Process == nil {
		return
	}
	_ = b.cmd.Process.Signal(syscall.SIGTERM)
	select {
	case <-b.done:
	case <-time.After(10 * time.Second):
		_ = b.cmd.Process.Kill()
		<-b.done
	}
	b.cmd = nil
}

// restart is the same broker, on the same state, with other options.
func (b *l67Broker) restart(t *testing.T, o l67BrokerOpts) {
	t.Helper()
	b.stop()
	b.opts = o
	b.write(t, o)
	b.start(t)
}

// port49 runs bin/port49 with args and returns its output and exit code.
func (b *l67Broker) port49(t *testing.T, args ...string) (string, int) {
	t.Helper()
	cmd := exec.Command(b.cli, args...)
	out, err := cmd.CombinedOutput()
	var ee *exec.ExitError
	switch {
	case err == nil:
		return string(out), 0
	case errors.As(err, &ee):
		return string(out), ee.ExitCode()
	}
	return string(out) + err.Error(), -1
}

// unlock clears name's failed-sign-in count at the broker (the operator's
// `port49 directory unlock`).
func (b *l67Broker) unlock(t *testing.T, name string) {
	t.Helper()
	if out, code := b.port49(t, "directory", "unlock", "--socket", b.admin, "user:"+name+"@corp.example.com"); code != 0 {
		t.Fatalf("INVALID: directory unlock %s: exit %d: %s", name, code, oneLineMax(out, 300))
	}
}

func (b *l67Broker) api(t *testing.T) *l67API {
	t.Helper()
	a, err := newL67API("https://"+b.addr, filepath.Join(b.pki, testpki.LabCA))
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// leakCheck fails the cell if the broker's log holds the person's password.
func (b *l67Broker) leakCheck(t *testing.T, x *l67X) {
	t.Helper()
	if strings.Contains(b.said(), x.pw) {
		x.fail("g (memory): the broker's log holds the person's password")
	}
}

// ---------------------------------------------------------------------------
// The sign-in API, as the CLI speaks it.
// ---------------------------------------------------------------------------

type l67API struct {
	base   string
	client *http.Client
	csr    string
}

type l67Answer struct {
	Status int
	Error  string
	Detail string
	Enroll *api.Enrollment
	Cert   bool
}

func newL67API(base, caFile string) (*l67API, error) {
	pemBytes, err := os.ReadFile(caFile)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(pemBytes)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		return nil, err
	}
	return &l67API{base: strings.TrimRight(base, "/"), csr: base64.RawURLEncoding.EncodeToString(der),
		client: &http.Client{Timeout: 90 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
			Transport:     &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: pool}}}}, nil
}

func (a *l67API) post(path string, body any) l67Answer {
	b, err := json.Marshal(body)
	if err != nil {
		return l67Answer{Error: "marshal"}
	}
	req, err := http.NewRequest(http.MethodPost, a.base+path, bytes.NewReader(b))
	if err != nil {
		return l67Answer{Error: "request"}
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := a.client.Do(req)
	if err != nil {
		return l67Answer{Error: "unreachable"}
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	ans := l67Answer{Status: resp.StatusCode}
	switch resp.StatusCode {
	case http.StatusOK:
		var out api.IssueResponse
		ans.Cert = json.Unmarshal(raw, &out) == nil && out.Certificate != ""
	case http.StatusAccepted:
		var e api.EnrollResponse
		if json.Unmarshal(raw, &e) == nil && e.Enroll.Handle != "" {
			ans.Enroll = &e.Enroll
		}
	default:
		var e api.Error
		_ = json.Unmarshal(raw, &e)
		ans.Error, ans.Detail = e.Error, oneLineMax(e.Detail, 200)
	}
	return ans
}

func (a *l67API) signIn(name, password, code string) l67Answer {
	return a.post("/v1/sign-in", api.SignInRequest{Name: name, Password: password, Code: code, CSR: a.csr})
}

func (a *l67API) confirm(handle, code string) l67Answer {
	return a.post("/v1/sign-in/confirm", api.ConfirmRequest{Handle: handle, Code: code, CSR: a.csr})
}

// ---------------------------------------------------------------------------
// A directory that stops: a TCP forwarder.
// ---------------------------------------------------------------------------

// tcpGate forwards a loopback port to a directory's, so the broker's directory
// can be stopped without stopping the container the other cells use.
type tcpGate struct {
	ln     net.Listener
	target string
	mu     sync.Mutex
	conns  []net.Conn
}

func newTCPGate(t *testing.T, target string) *tcpGate {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	g := &tcpGate{ln: ln, target: target}
	t.Cleanup(g.stop)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			up, err := net.DialTimeout("tcp", target, 10*time.Second)
			if err != nil {
				c.Close()
				continue
			}
			g.mu.Lock()
			g.conns = append(g.conns, c, up)
			g.mu.Unlock()
			go func() { _, _ = io.Copy(up, c); up.Close() }()
			go func() { _, _ = io.Copy(c, up); c.Close() }()
		}
	}()
	return g
}

func (g *tcpGate) port() string {
	_, p, _ := net.SplitHostPort(g.ln.Addr().String())
	return p
}

// stop closes the listener and every connection through it: the directory is
// gone, as a stopped container's is.
func (g *tcpGate) stop() {
	_ = g.ln.Close()
	g.mu.Lock()
	defer g.mu.Unlock()
	for _, c := range g.conns {
		_ = c.Close()
	}
	g.conns = nil
}

// ---------------------------------------------------------------------------
// bin/port49 under a pty.
// ---------------------------------------------------------------------------

// l67CLI is bin/port49 as a person runs it: its own home (where the issued
// key and certificate are kept), agent socket and broker.
type l67CLI struct {
	bin, home, sock, broker, ca string
	env                         []string
	agent                       *l56CLI
}

func newL67CLI(t *testing.T, broker, ca string) *l67CLI {
	t.Helper()
	_, bin := l67Bins(t)
	home, err := os.MkdirTemp("", "p49l67h")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(home) })
	var env []string
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, "PORT49_CONFIG=") && !strings.HasPrefix(kv, "XDG_CONFIG_HOME=") {
			env = append(env, kv)
		}
	}
	c := &l67CLI{bin: bin, home: home, sock: filepath.Join(home, "run", "agent.sock"), broker: broker, ca: ca,
		env: append(env, "HOME="+home, "BROWSER=", "DISPLAY=", "WAYLAND_DISPLAY=")}
	c.agent = &l56CLI{sock: c.sock}
	t.Cleanup(c.agent.stopAgent)
	return c
}

// l67Term is a pty: the master the test types on and reads, the slave the CLI
// takes for its stdin, stdout and stderr (it shows a secret only to a terminal).
type l67Term struct {
	master *os.File
	mu     sync.Mutex
	buf    bytes.Buffer
}

func newL67Term(t *testing.T) (*l67Term, *os.File) {
	t.Helper()
	m, s := l56Pty(t)
	p := &l67Term{master: m}
	go func() {
		chunk := make([]byte, 4096)
		for {
			n, err := m.Read(chunk)
			if n > 0 {
				p.mu.Lock()
				p.buf.Write(chunk[:n])
				p.mu.Unlock()
			}
			if err != nil {
				return
			}
		}
	}()
	return p, s
}

func (p *l67Term) text() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.buf.String()
}

// waitFor is the end of the first sub in the screen at or after from, within d.
func (p *l67Term) waitFor(sub string, from int, d time.Duration) (int, bool) {
	for deadline := time.Now().Add(d); time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
		s := p.text()
		if from <= len(s) {
			if i := strings.Index(s[from:], sub); i >= 0 {
				return from + i + len(sub), true
			}
		}
	}
	return 0, false
}

func (p *l67Term) send(s string) {
	time.Sleep(150 * time.Millisecond) // the prompt has turned echo off
	_, _ = p.master.WriteString(s + "\n")
}

// l67LoginIn is one `port49 login --directory` and what is typed to it.
type l67LoginIn struct {
	name, password string
	code           func() string // the code typed at the code prompt; nil is none, which enrols
	enroll         bool
	extra          []string
}

// l67LoginOut is what a login did. Said is the lines the CLI wrote that name
// no secret, scrubbed; the screen itself (which holds the QR and the key) is
// never kept.
type l67LoginOut struct {
	Exit     int
	Enrolled bool
	Secret   []byte
	Step     int64
	Said     string
}

var l67Printable = regexp.MustCompile(`^[\x20-\x7e]+$`)

// l67Said keeps the lines of a screen that are plain text and hold none of the
// secrets, joined.
func l67Said(screen string, secrets ...string) string {
	var out []string
	for _, ln := range strings.Split(strings.ReplaceAll(screen, "\r", ""), "\n") {
		ln = strings.TrimSpace(ln)
		if ln == "" || !l67Printable.MatchString(ln) || strings.HasPrefix(ln, "key:") || strings.HasPrefix(ln, "directory name [") {
			continue
		}
		for _, s := range secrets {
			if s != "" {
				ln = strings.ReplaceAll(ln, s, "<redacted>")
			}
		}
		out = append(out, ln)
	}
	return oneLineMax(strings.Join(out, " | "), 400)
}

func (c *l67CLI) login(t *testing.T, in l67LoginIn) l67LoginOut {
	t.Helper()
	term, slave := newL67Term(t)
	args := append([]string{"login", "--directory", "--name", in.name, "--broker", c.broker, "--broker-ca", c.ca, "--socket", c.sock}, in.extra...)
	cmd := exec.Command(c.bin, args...)
	cmd.Env = c.env
	cmd.Stdin, cmd.Stdout, cmd.Stderr = slave, slave, slave
	if err := cmd.Start(); err != nil {
		t.Fatalf("start port49 login: %v", err)
	}
	slave.Close()
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	var out l67LoginOut
	var typed []string
	finish := func() l67LoginOut {
		select {
		case err := <-done:
			var ee *exec.ExitError
			switch {
			case err == nil:
				out.Exit = 0
			case errors.As(err, &ee):
				out.Exit = ee.ExitCode()
			default:
				out.Exit = -1
			}
		case <-time.After(90 * time.Second):
			_ = cmd.Process.Kill()
			<-done
			out.Exit = -1
			out.Said = "timed out"
			return out
		}
		time.Sleep(200 * time.Millisecond) // the last of the screen
		secrets := append([]string{in.password}, typed...)
		if out.Secret != nil {
			secrets = append(secrets, strings.ToLower(l67Base32(out.Secret)), l67Base32(out.Secret))
		}
		out.Said = l67Said(term.text(), secrets...)
		return out
	}
	stuck := func(what string) l67LoginOut {
		_ = cmd.Process.Kill()
		<-done
		out.Exit = -1
		out.Said = "the CLI never showed " + what + "; its screen: " + l67Said(term.text(), in.password)
		return out
	}
	pos, ok := term.waitFor("]: ", 0, 60*time.Second)
	if !ok {
		return stuck("the name prompt")
	}
	term.send(in.name)
	if pos, ok = term.waitFor("password: ", pos, 30*time.Second); !ok {
		return stuck("the password prompt")
	}
	term.send(in.password)
	if pos, ok = term.waitFor("none yet): ", pos, 30*time.Second); !ok {
		// The broker refused before the code prompt, or the CLI did.
		return finish()
	}
	code := ""
	if in.code != nil {
		code = in.code()
		typed = append(typed, code)
	}
	term.send(code)
	if !in.enroll {
		return finish()
	}
	kpos, ok := term.waitFor("key: ", pos, 60*time.Second)
	if !ok {
		return finish() // the broker refused, or answered with no enrollment
	}
	eol, ok := term.waitFor("\n", kpos, 10*time.Second)
	if !ok {
		return stuck("the end of the key line")
	}
	line := strings.TrimSpace(strings.ReplaceAll(term.text()[kpos:eol], "\r", ""))
	secret, err := totp.DecodeSecret(strings.ToUpper(strings.ReplaceAll(line, " ", "")))
	if err != nil {
		return stuck("a key it could read")
	}
	out.Secret = secret
	if _, ok = term.waitFor("first code from your authenticator: ", eol, 30*time.Second); !ok {
		return stuck("the confirm prompt")
	}
	step, wait := l67NextStep(0, time.Now())
	time.Sleep(wait)
	first, err := l67CodeAt(secret, step)
	if err != nil {
		return stuck("a code")
	}
	typed = append(typed, first)
	out.Step = step
	term.send(first)
	out.Enrolled = true
	return finish()
}

// l67Base32 is a secret as the CLI shows it, without the grouping.
func l67Base32(secret []byte) string {
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secret)
}

type l67TokenOut struct {
	Exit   int
	Minted bool
	Said   string
}

// token is `port49 token device` against the CLI's agent. The token is the
// whole of stdout and is never kept: only that one line came.
func (c *l67CLI) token(t *testing.T, device string) l67TokenOut {
	t.Helper()
	cmd := exec.Command(c.bin, "token", "--socket", c.sock, device)
	cmd.Env = c.env
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	out := l67TokenOut{}
	var ee *exec.ExitError
	switch {
	case err == nil:
	case errors.As(err, &ee):
		out.Exit = ee.ExitCode()
	default:
		out.Exit = -1
	}
	tok := strings.TrimSpace(stdout.String())
	out.Minted = out.Exit == 0 && tok != "" && !strings.ContainsAny(tok, " \n")
	out.Said = l67Said(stderr.String(), tok)
	return out
}
