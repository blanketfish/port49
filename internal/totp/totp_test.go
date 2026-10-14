package totp

import (
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"
)

// RFC 6238 Appendix B, SHA-1, the last 6 of each 8-digit value.
var rfcSecret = []byte("12345678901234567890")

func TestRFC6238Vectors(t *testing.T) {
	for _, v := range []struct {
		at   int64
		code string
	}{{59, "287082"}, {1111111109, "081804"}, {1111111111, "050471"}, {1234567890, "005924"},
		{2000000000, "279037"}, {20000000000, "353130"}} {
		step, err := Check(rfcSecret, v.code, time.Unix(v.at, 0), 0)
		if err != nil || step != v.at/30 {
			t.Errorf("at %d: step %d, %v", v.at, step, err)
		}
	}
}

func TestOneStepEitherSideIsAccepted(t *testing.T) {
	at := time.Unix(1111111111, 0)
	for _, d := range []time.Duration{-Period, Period} {
		if _, err := Check(rfcSecret, "050471", at.Add(d), 0); err != nil {
			t.Errorf("%s away: %v", d, err)
		}
	}
}

func TestThreeStepsAwayIsSaidAsSkew(t *testing.T) {
	_, err := Check(rfcSecret, "050471", time.Unix(1111111111, 0).Add(3*Period), 0)
	var s *Skewed
	if !errors.As(err, &s) || s.By != -3*Period {
		t.Fatalf("%v", err)
	}
}

func TestAStepIsTakenOnce(t *testing.T) {
	at := time.Unix(1111111111, 0)
	step, err := Check(rfcSecret, "050471", at, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Check(rfcSecret, "050471", at, step); !errors.Is(err, ErrReplayed) {
		t.Fatalf("a step taken twice: %v", err)
	}
	// An earlier step than the last taken is refused too.
	if _, err := Check(rfcSecret, "081804", time.Unix(1111111109, 0), step); !errors.Is(err, ErrReplayed) {
		t.Fatalf("an earlier step: %v", err)
	}
}

func TestMalformedCodesAreWrong(t *testing.T) {
	for _, c := range []string{"", "05047", "0504710", "05047a", " 050471", "０５０４７１"} {
		if _, err := Check(rfcSecret, c, time.Unix(1111111111, 0), 0); !errors.Is(err, ErrWrongCode) {
			t.Errorf("%q: %v", c, err)
		}
	}
}

func TestNewSecretIsRandomAndSized(t *testing.T) {
	a, _ := NewSecret()
	b, _ := NewSecret()
	if len(a) != SecretSize || string(a) == string(b) {
		t.Fatal("not 20 random bytes")
	}
}

func TestTheURIIsWhatAuthenticatorsRead(t *testing.T) {
	u, err := url.Parse(URI(rfcSecret, "port49 (broker.example.com)", "alice@example.com"))
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	if u.Scheme != "otpauth" || u.Host != "totp" || !strings.HasPrefix(u.Path, "/port49 (broker.example.com):alice@example.com") ||
		q.Get("secret") != "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ" || q.Get("issuer") != "port49 (broker.example.com)" ||
		q.Get("algorithm") != "SHA1" || q.Get("digits") != "6" || q.Get("period") != "30" {
		t.Fatalf("the URI is not the Key URI Format an authenticator reads")
	}
	if s, err := DecodeSecret(q.Get("secret")); err != nil || string(s) != string(rfcSecret) {
		t.Fatalf("the URI's secret does not decode back: %v", err)
	}
}

// Code is what an authenticator shows: the RFC's vector, and what Check takes.
func TestCodeIsTheAuthenticators(t *testing.T) {
	at := time.Unix(1111111111, 0)
	c, err := Code(rfcSecret, at)
	if err != nil || c != "050471" {
		t.Fatalf("the code at the RFC's vector is wrong: %v", err)
	}
	if _, err := Check(rfcSecret, c, at, 0); err != nil {
		t.Fatal(err)
	}
}
