package directory

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/go-ldap/ldap/v3"
)

// SignInEntry is the entry a name typed at a directory sign-in names (plan
// 9e; decision 47 ruling 3), and the server that answered.
type SignInEntry struct {
	Identity
	Server    Server
	CreatedAt time.Time // whenCreated or createTimestamp; zero when neither was read
}

// ErrPasswordRefused is a person's bind the directory refused.
var ErrPasswordRefused = errors.New("directory: the password was refused")

// ErrEmptyPassword is a password refused before any dial (RFC 4513 §5.1.2).
var ErrEmptyPassword = errors.New("directory: an empty password is never sent")

// PasswordRefusal is how the directory refused a person's bind: its LDAP
// result, and AD's data code or OpenLDAP's ppolicy error when it gave one
// (ruling 6). It never holds the server's message.
type PasswordRefusal struct {
	Result int
	Data   string // "52e", "532", …, or "password_expired", "account_locked", "change_after_reset"
}

func (p *PasswordRefusal) Error() string {
	if p.Data == "" {
		return fmt.Sprintf("%s (LDAP result %d)", ErrPasswordRefused, p.Result)
	}
	return fmt.Sprintf("%s (LDAP result %d, %s)", ErrPasswordRefused, p.Result, p.Data)
}

func (p *PasswordRefusal) Unwrap() error { return ErrPasswordRefused }

// State is whether the refusal names the account's state rather than a
// wrong password (ruling 7): every Data but "", "52e" and "525".
func (p *PasswordRefusal) State() bool {
	return p.Data != "" && p.Data != "52e" && p.Data != "525"
}

// adData is AD's data code in a bind's diagnostic message, kept only when it
// is one ruling 6 names; the message itself is never kept.
var adData = regexp.MustCompile(`\bdata ([0-9a-f]{3,4})\b`)

var knownData = map[string]bool{"52e": true, "525": true, "530": true, "531": true, "532": true,
	"533": true, "701": true, "773": true, "775": true}

// SignInEntry finds the one entry whose username_attribute is name, under
// user_filter and filter, and reads it as a person's. Its errors may hold
// the typed name and never reach a log.
func (r *Resolver) SignInEntry(ctx context.Context, name, filter string) (SignInEntry, error) {
	var out SignInEntry
	q := fmt.Sprintf("(&%s%s(%s=%s))", r.Cfg.UserFilter, filter, r.Cfg.UsernameAttribute, ldap.EscapeFilter(name))
	attrs := append(r.Cfg.entryAttrs(), "whenCreated", "createTimestamp")
	srv, err := r.Pool.Do(ctx, func(s Searcher) error {
		// Pool.Do reruns this on the next server after a fault.
		out = SignInEntry{}
		e, err := r.Cfg.oneEntry(s, q, attrs)
		if err != nil {
			return err
		}
		if err := r.Cfg.notWorkload(e); err != nil {
			return err
		}
		id, err := r.Cfg.identityOf(e)
		if err != nil {
			return err
		}
		if err := r.Cfg.principalUnique(s, id); err != nil {
			return err
		}
		if err := r.Cfg.usernameUnique(s, id); err != nil {
			return err
		}
		out.Identity = id
		for _, a := range []string{"whenCreated", "createTimestamp"} {
			if v := e.GetAttributeValue(a); v != "" {
				if t, err := ber.ParseGeneralizedTime([]byte(v)); err == nil {
					out.CreatedAt = t
					break
				}
			}
		}
		return nil
	})
	if err != nil {
		return SignInEntry{}, err
	}
	out.Server = srv
	return out, nil
}

// CheckPassword is one bind as dn with password, on a connection of its own
// that is closed after it: nil for a bound person, *PasswordRefusal for a
// refusal, ErrEmptyPassword before any dial, ErrUnavailable when the server
// did not answer. It never uses r.Pool, so a refusal moves no breaker and
// starts no hold-off. The password is not logged, put in an error or kept.
func (r *Resolver) CheckPassword(ctx context.Context, s Server, dn, password string) error {
	if strings.TrimSpace(password) == "" {
		return ErrEmptyPassword
	}
	dial := r.PersonDial
	if dial == nil {
		dial = func(ctx context.Context, s Server) (PersonConn, error) { return dialPerson(ctx, r.Cfg, s) }
	}
	conn, err := dial(ctx, s)
	if err != nil {
		return fmt.Errorf("%w: %s: %v", ErrUnavailable, s.Label(), err)
	}
	defer conn.Close()
	done := make(chan error, 1)
	var res *ldap.SimpleBindResult
	go func() {
		var err error
		res, err = conn.SimpleBind(&ldap.SimpleBindRequest{Username: dn, Password: password,
			Controls: []ldap.Control{ldap.NewControlBeheraPasswordPolicy()}})
		done <- err
	}()
	select {
	case err = <-done:
	case <-ctx.Done():
		_ = conn.Close()
		return fmt.Errorf("%w: %s: %v", ErrUnavailable, s.Label(), ctx.Err())
	}
	var p *PasswordRefusal
	if err != nil {
		var le *ldap.Error
		if !errors.As(err, &le) || le.ResultCode >= 200 {
			return fmt.Errorf("%w: %s: the bind did not complete", ErrUnavailable, s.Label())
		}
		p = &PasswordRefusal{Result: int(le.ResultCode)}
		if le.Err != nil {
			if m := adData.FindStringSubmatch(le.Err.Error()); m != nil && knownData[m[1]] {
				p.Data = m[1]
			}
		}
	}
	if res != nil {
		if d := ppolicyData(res.Controls); d != "" {
			if p == nil { // a bind the server accepted, with a password it says must change (I4)
				p = &PasswordRefusal{Result: 0}
			}
			p.Data = d
		}
	}
	if p == nil {
		return nil
	}
	return p
}

// ppolicyData is the error a Behera password-policy control among controls
// carries (draft-behera-ldap-password-policy-10 §6.2), "" for none. Only its
// Error member is read: graceAuthNsRemaining is a success.
func ppolicyData(controls []ldap.Control) string {
	for _, c := range controls {
		if pp, ok := c.(*ldap.ControlBeheraPasswordPolicy); ok {
			switch pp.Error {
			case 0:
				return "password_expired"
			case 1:
				return "account_locked"
			case 2:
				return "change_after_reset"
			}
		}
	}
	return ""
}

// PersonConn is the one connection a person's bind is made on.
// *ldap.Conn is one.
type PersonConn interface {
	SimpleBind(*ldap.SimpleBindRequest) (*ldap.SimpleBindResult, error)
	Close() error
}

// dialPerson dials s, secures it (LDAPS, or StartTLS), and returns the
// connection unbound. It presents no client certificate whatever the
// broker's bind mechanism (plan 9e, D3).
func dialPerson(ctx context.Context, cfg Config, s Server) (PersonConn, error) {
	conn, err := dialTLS(ctx, cfg, s, &Credentials{})
	if err != nil {
		return nil, err
	}
	return conn, nil
}

// personTLS is the TLS a person's connection uses: tlsConfig(cfg, s,
// &Credentials{}), never a client certificate.
func personTLS(cfg Config, s Server) (*tls.Config, error) {
	return tlsConfig(cfg, s, &Credentials{})
}
